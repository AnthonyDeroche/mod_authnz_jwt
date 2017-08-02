
/*
* Copyright 2016 Anthony Deroche <anthony@deroche.me>
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>

// RFC 7519 compliant library
#include "jwt.h"
#include <errno.h>
//JSON library
#include "jansson.h"

#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_base64.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_provider.h"

#include "mod_auth.h"

#define JWT_LOGIN_HANDLER "jwt-login-handler"
#define JWT_LOGOUT_HANDLER "jwt-login-handler"
#define USER_INDEX 0
#define PASSWORD_INDEX 1
#define FORM_SIZE 512
#define MAX_KEY_LEN 16384

#define DEFAULT_EXP_DELAY 1800
#define DEFAULT_NBF_DELAY 0
#define DEFAULT_LEEWAY 0

#define DEFAULT_FORM_USERNAME "user"
#define DEFAULT_FORM_PASSWORD "password"
#define DEFAULT_ATTRIBUTE_USERNAME "user"
#define DEFAULT_SIGNATURE_ALGORITHM "HS256"


/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  CONFIGURATION STRUCTURE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  */

typedef struct {
	authn_provider_list *providers;

	const char* signature_algorithm;
	int signature_algorithm_set;

	const char* signature_shared_secret;
	int signature_shared_secret_set;

	const char* signature_public_key_file;
	int signature_public_key_file_set;

	const char* signature_private_key_file;
	int signature_private_key_file_set;

	int exp_delay;
	int exp_delay_set;

	int nbf_delay;
	int nbf_delay_set;

	int leeway;
	int leeway_set;

	const char* iss;
	int iss_set;

	const char* aud;
	int aud_set;

	const char* form_username;
	int form_username_set;

	const char* form_password;
	int form_password_set;

	const char* attribute_username;
	int attribute_username_set;

	char *dir;

} auth_jwt_config_rec;

typedef enum { 
	dir_signature_algorithm, 
	dir_signature_shared_secret, 
	dir_signature_public_key_file,
	dir_signature_private_key_file,
	dir_exp_delay, 
	dir_nbf_delay, 
	dir_iss,
	dir_aud, 
	dir_leeway,
	dir_form_username,
	dir_form_password,
	dir_attribute_username
} jwt_directive;

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  FUNCTIONS HEADERS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  */


static void *create_auth_jwt_dir_config(apr_pool_t *p, char *d);
static void *create_auth_jwt_config(apr_pool_t * p, server_rec *s);
static void *merge_auth_jwt_dir_config(apr_pool_t *p, void* basev, void* addv);
static void *merge_auth_jwt_config(apr_pool_t *p, void* basev, void* addv);
static void register_hooks(apr_pool_t * p);

static const char *add_authn_provider(cmd_parms * cmd, void *config, const char *arg);
static const char *set_jwt_param(cmd_parms * cmd, void* config, const char* value);
static const char *set_jwt_int_param(cmd_parms * cmd, void* config, const char* value);
static const char* get_config_value(request_rec *r, jwt_directive directive);
static const int get_config_int_value(request_rec *r, jwt_directive directive);

static const char *jwt_parse_config(cmd_parms *cmd, const char *require_line, const void **parsed_require_line);
static authz_status jwtclaim_check_authorization(request_rec *r, const char* require_args, const void *parsed_require_args);
static authz_status jwtclaimarray_check_authorization(request_rec *r, const char* require_args, const void *parsed_require_args);
static const authz_provider authz_jwtclaim_provider = {
	&jwtclaim_check_authorization,
	&jwt_parse_config
};
static const authz_provider authz_jwtclaimarray_provider = {
	&jwtclaimarray_check_authorization,
	&jwt_parse_config
};

static int auth_jwt_login_handler(request_rec *r);
static int check_authn(request_rec *r, const char *username, const char *password);
static int create_token(request_rec *r, char** token_str, const char* username);

static int auth_jwt_authn_with_token(request_rec *r);

static void get_encode_key(request_rec* r, const char* algorithm, unsigned char* key, unsigned int* keylen);
static void get_decode_key(request_rec* r, unsigned char* key, unsigned int* keylen);
static int token_check(request_rec *r, jwt_t **jwt, const char *token, const unsigned char *key, unsigned int keylen);
static int token_decode(jwt_t **jwt, const char* token, const unsigned char *key, unsigned int keylen);
static int token_new(jwt_t **jwt);
static const char* token_get_claim(jwt_t *token, const char* claim);
static long token_get_claim_int(jwt_t *token, const char* claim);
static int token_add_claim(jwt_t *jwt, const char *claim, const char *val);
static int token_add_claim_int(jwt_t *jwt, const char *claim, long val);
static void token_free(jwt_t *token);
static int token_set_alg(request_rec *r, jwt_t *jwt, const char* alg, const unsigned char *key, unsigned int keylen);
static char *token_encode_str(jwt_t *jwt);
static char** token_get_claim_array_of_string(request_rec* r, jwt_t *token, const char* claim, int* len);
static json_t* token_get_claim_array(request_rec* r, jwt_t *token, const char* claim);
static json_t* token_get_claim_json(request_rec* r, jwt_t *token, const char* claim);
static const char* token_get_alg(jwt_t *jwt);
static jwt_alg_t parse_alg(const char* signature_algorithm);

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  DECLARE DIRECTIVES ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  */

static const command_rec auth_jwt_cmds[] =
{

	AP_INIT_TAKE1("AuthJWTSignatureAlgorithm", set_jwt_param, (void *)dir_signature_algorithm, RSRC_CONF|OR_AUTHCFG,
					"The algorithm to use to sign tokens"),
	AP_INIT_TAKE1("AuthJWTSignatureSharedSecret", set_jwt_param, (void *)dir_signature_shared_secret, RSRC_CONF|OR_AUTHCFG,
					 "The shared secret to use to sign tokens with HMACs"),
   	AP_INIT_TAKE1("AuthJWTSignaturePublicKeyFile", set_jwt_param, (void *)dir_signature_public_key_file, RSRC_CONF|OR_AUTHCFG,
					 "The file containing public key used to check signatures"),
   	AP_INIT_TAKE1("AuthJWTSignaturePrivateKeyFile", set_jwt_param, (void *)dir_signature_private_key_file, RSRC_CONF|OR_AUTHCFG,
					 "The file containing private key used to sign tokens"),
   	AP_INIT_TAKE1("AuthJWTIss", set_jwt_param, (void *)dir_iss, RSRC_CONF|OR_AUTHCFG,
					 "The issuer of delievered tokens"),
   	AP_INIT_TAKE1("AuthJWTAud", set_jwt_param, (void *)dir_aud, RSRC_CONF|OR_AUTHCFG,
					 "The audience of delivered tokens"),
   	AP_INIT_TAKE1("AuthJWTExpDelay", set_jwt_int_param, (void *)dir_exp_delay, RSRC_CONF|OR_AUTHCFG,
					 "The time delay in seconds after which delivered tokens are considered invalid"),
   	AP_INIT_TAKE1("AuthJWTNbfDelay", set_jwt_int_param, (void *)dir_nbf_delay, RSRC_CONF|OR_AUTHCFG,
					 "The time delay in seconds before which delivered tokens must not be processed"),
   	AP_INIT_TAKE1("AuthJWTLeeway", set_jwt_int_param, (void *)dir_leeway, RSRC_CONF|OR_AUTHCFG,
					 "The leeway to account for clock skew in token validation process"),
   	AP_INIT_ITERATE("AuthJWTProvider", add_authn_provider, NULL, OR_AUTHCFG,
				"Specify the auth providers for a directory or location"),
   	AP_INIT_TAKE1("AuthJWTFormUsername", set_jwt_param, (void *)dir_form_username, RSRC_CONF|OR_AUTHCFG,
					 "The name of the field containing the username in authentication process"),
   	AP_INIT_TAKE1("AuthJWTFormPassword", set_jwt_param, (void *)dir_form_password, RSRC_CONF|OR_AUTHCFG,
					 "The name of the field containing the password in authentication process"),
   	AP_INIT_TAKE1("AuthJWTAttributeUsername", set_jwt_param, (void *)dir_attribute_username, RSRC_CONF|OR_AUTHCFG,
					 "The name of the attribute containing the username in the token"),
	{NULL}
};

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  DEFAULT CONFIGURATION ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  */

/* PER DIR CONFIGURATION */
static void *create_auth_jwt_dir_config(apr_pool_t *p, char *d){
	auth_jwt_config_rec *conf = (auth_jwt_config_rec*) apr_pcalloc(p, sizeof(*conf));
	conf->dir = d;

	conf->signature_algorithm_set = 0;
	conf->signature_shared_secret_set = 0;
	conf->signature_public_key_file_set = 0;
	conf->signature_private_key_file_set = 0;
	conf->exp_delay_set = 0;
	conf->nbf_delay_set = 0;
	conf->leeway_set = 0;
	conf->iss_set = 0;
	conf->aud_set = 0;
	conf->form_username_set=0;
	conf->form_password_set=0;
	conf->attribute_username_set=0;

	return (void *)conf;
}

/* GLOBAL CONFIGURATION */
static void *create_auth_jwt_config(apr_pool_t * p, server_rec *s){

	auth_jwt_config_rec *conf = (auth_jwt_config_rec*) apr_pcalloc(p, sizeof(*conf));

	conf->signature_algorithm_set = 0;
	conf->signature_shared_secret_set = 0;
	conf->signature_public_key_file_set = 0;
	conf->signature_private_key_file_set = 0;
	conf->exp_delay_set = 0;
	conf->nbf_delay_set = 0;
	conf->leeway_set = 0;
	conf->iss_set = 0;
	conf->aud_set = 0;
	conf->form_username_set=0;
	conf->form_password_set=0;
	conf->attribute_username_set=0;

	return (void *)conf;
}

static void* merge_auth_jwt_dir_config(apr_pool_t *p, void* basev, void* addv){
	auth_jwt_config_rec *base = (auth_jwt_config_rec *)basev;
	auth_jwt_config_rec *add = (auth_jwt_config_rec *)addv;
	auth_jwt_config_rec *new = (auth_jwt_config_rec *) apr_pcalloc(p, sizeof(auth_jwt_config_rec));
	
	new->providers = !add->providers ? base->providers : add->providers;
	new->signature_algorithm = (add->signature_algorithm_set == 0) ? base->signature_algorithm : add->signature_algorithm;
	new->signature_algorithm_set = base->signature_algorithm_set || add->signature_algorithm_set;

	new->signature_shared_secret = (add->signature_shared_secret_set == 0) ? base->signature_shared_secret : add->signature_shared_secret;
	new->signature_shared_secret_set = base->signature_shared_secret_set || add->signature_shared_secret_set;
	new->signature_public_key_file = (add->signature_public_key_file_set == 0) ? base->signature_public_key_file : add->signature_public_key_file;
	new->signature_public_key_file_set = base->signature_public_key_file_set || add->signature_public_key_file_set;
	new->signature_private_key_file = (add->signature_private_key_file_set == 0) ? base->signature_private_key_file : add->signature_private_key_file;
	new->signature_private_key_file_set = base->signature_private_key_file_set || add->signature_private_key_file_set;

	new->exp_delay = (add->exp_delay_set == 0) ? base->exp_delay : add->exp_delay;
	new->exp_delay_set = base->exp_delay_set || add->exp_delay_set;
	new->nbf_delay = (add->nbf_delay_set == 0) ? base->nbf_delay : add->nbf_delay;
	new->nbf_delay_set = base->nbf_delay_set || add->nbf_delay_set;
	new->leeway = (add->leeway_set == 0) ? base->leeway : add->leeway;
	new->leeway_set = base->leeway_set || add->leeway_set;
	new->iss = (add->iss_set == 0) ? base->iss : add->iss;
	new->iss_set = base->iss_set || add->iss_set;
	new->aud = (add->aud_set == 0) ? base->aud : add->aud;
	new->aud_set = base->aud_set || add->aud_set;
	new->form_username = (add->form_username_set == 0) ? base->form_username : add->form_username;
	new->form_username_set = base->form_username_set || add->form_username_set;
	new->form_password = (add->form_password_set == 0) ? base->form_password : add->form_password;
	new->form_password_set = base->form_password_set || add->form_password_set;
	new->attribute_username = (add->attribute_username_set == 0) ? base->attribute_username : add->attribute_username;
	new->attribute_username_set = base->attribute_username_set || add->attribute_username_set;
	return (void*)new;
}

static void* merge_auth_jwt_config(apr_pool_t *p, void* basev, void* addv){
	return merge_auth_jwt_dir_config(p, basev, addv);
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  DECLARE MODULE IN HTTPD CORE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  */

AP_DECLARE_MODULE(auth_jwt) = {
  	STANDARD20_MODULE_STUFF,
  	create_auth_jwt_dir_config,
  	merge_auth_jwt_dir_config,
  	create_auth_jwt_config,
  	merge_auth_jwt_config,
  	auth_jwt_cmds,
  	register_hooks
};


/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  FILL OUT CONF STRUCTURES ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  */

static const char* get_config_value(request_rec *r, jwt_directive directive){

	auth_jwt_config_rec *dconf = (auth_jwt_config_rec *) ap_get_module_config(r->per_dir_config, &auth_jwt_module);

	auth_jwt_config_rec *sconf = (auth_jwt_config_rec *) ap_get_module_config(r->server->module_config, &auth_jwt_module);
	const char* value;

	switch ((jwt_directive) directive) {
		case dir_signature_algorithm:
			if(dconf->signature_algorithm_set && dconf->signature_algorithm){
				value = dconf->signature_algorithm;
			}else if(sconf->signature_algorithm){
				value = sconf->signature_algorithm;
			}else{
				return DEFAULT_SIGNATURE_ALGORITHM;
			}
			break;
		case dir_signature_shared_secret:
			if(dconf->signature_shared_secret_set && dconf->signature_shared_secret){
				value = dconf->signature_shared_secret;
			}else if(sconf->signature_shared_secret_set && sconf->signature_shared_secret){
				value = sconf->signature_shared_secret;
			}else{
				return NULL;
			}
			break;
		case dir_signature_public_key_file:
			if(dconf->signature_public_key_file_set && dconf->signature_public_key_file){
				value = dconf->signature_public_key_file;
			}else if(sconf->signature_public_key_file_set && sconf->signature_public_key_file){
				value = sconf->signature_public_key_file;
			}else{
				return NULL;
			}
			break;
		case dir_signature_private_key_file:
			if(dconf->signature_private_key_file_set && dconf->signature_private_key_file){
				value = dconf->signature_private_key_file;
			}else if(sconf->signature_private_key_file_set && sconf->signature_private_key_file){
				value = sconf->signature_private_key_file;
			}else{
				return NULL;
			}
			break;
		case dir_iss:
			if(dconf->iss_set && dconf->iss){
				value = (void*)dconf->iss;
			}else if(sconf->iss_set && sconf->iss){
				value = (void*)sconf->iss;
			}else{
				return NULL;
			}
			break;
		case dir_aud:
			if(dconf->aud_set && dconf->aud){
				value = dconf->aud;
			}else if(sconf->iss_set && sconf->aud){
				value = sconf->aud;
			}else{
				return NULL;
			}
			break;
 		case dir_form_username:
			if(dconf->form_username_set && dconf->form_username){
				value = dconf->form_username;
			}else if(sconf->form_username_set && sconf->form_username){
				value = sconf->form_username;
			}else{
				return DEFAULT_FORM_USERNAME;
			}
			break;
		case dir_form_password:
			if(dconf->form_password_set && dconf->form_password){
				value = dconf->form_password;
			}else if(sconf->form_password_set && sconf->form_password){
				value = sconf->form_password;
			}else{
				return DEFAULT_FORM_PASSWORD;
			}
			break;
		case dir_attribute_username:
			if(dconf->attribute_username_set && dconf->attribute_username){
				value = dconf->attribute_username;
			}else if(sconf->attribute_username_set && sconf->attribute_username){
				value = sconf->attribute_username;
			}else{
				return DEFAULT_ATTRIBUTE_USERNAME;
			}
			break;
		default:
			return NULL;
	}
	return value;
}

static const int get_config_int_value(request_rec *r, jwt_directive directive){
    auth_jwt_config_rec *dconf = (auth_jwt_config_rec *) ap_get_module_config(r->per_dir_config, &auth_jwt_module);

	auth_jwt_config_rec *sconf = (auth_jwt_config_rec *) ap_get_module_config(r->server->module_config, &auth_jwt_module);
    int value;
    switch ((jwt_directive) directive) {
        case dir_exp_delay:
            if(dconf->exp_delay_set){
                    value = dconf->exp_delay;
            }else if(sconf->exp_delay_set){
                    value = sconf->exp_delay;
            }else{
                    return DEFAULT_EXP_DELAY;
            }
            break;
        case dir_nbf_delay:
            if(dconf->nbf_delay_set){
                    value = dconf->nbf_delay;
            }else if(sconf->nbf_delay_set){
                    value = sconf->nbf_delay;
            }else{
                    return DEFAULT_NBF_DELAY;
            }
            break;
        case dir_leeway:
            if(dconf->leeway){
                    value = dconf->leeway;
            }else if(sconf->leeway_set){
                    value = sconf->leeway;
            }else{
                    return DEFAULT_LEEWAY;
            }
            break;
    }
    return (const int)value;
}


/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  REGISTER HOOKS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  */

static void register_hooks(apr_pool_t * p){
	ap_hook_handler(auth_jwt_login_handler, NULL, NULL, APR_HOOK_MIDDLE);
 	ap_hook_check_authn(auth_jwt_authn_with_token, NULL, NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "jwt-claim", AUTHZ_PROVIDER_VERSION, &authz_jwtclaim_provider, AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "jwt-claim-array", AUTHZ_PROVIDER_VERSION, &authz_jwtclaimarray_provider, AP_AUTH_INTERNAL_PER_CONF);
}



/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  DIRECTIVE HANDLERS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  */

static const char *add_authn_provider(cmd_parms * cmd, void *config, const char *arg)
{
	auth_jwt_config_rec *conf = (auth_jwt_config_rec *) config;
	authn_provider_list *newp;

	newp = apr_pcalloc(cmd->pool, sizeof(authn_provider_list));
	newp->provider_name = arg;

	newp->provider = ap_lookup_provider(AUTHN_PROVIDER_GROUP, newp->provider_name, AUTHN_PROVIDER_VERSION);

	if (newp->provider == NULL) {
		return apr_psprintf(cmd->pool,"Unknown Authn provider: %s", newp->provider_name);
	}

	if (!newp->provider->check_password) {
		return apr_psprintf(cmd->pool, "The '%s' Authn provider doesn't support JWT authentication", newp->provider_name);
	}

	if (!conf->providers) {
		conf->providers = newp;
	}
	else {
		authn_provider_list *last = conf->providers;

		while (last->next) {
			last = last->next;
		}
		last->next = newp;
	}

	return NULL;
}

static const char *set_jwt_param(cmd_parms * cmd, void* config, const char* value){

	auth_jwt_config_rec *conf;
	if(!cmd->path){
		conf = (auth_jwt_config_rec *) ap_get_module_config(cmd->server->module_config, &auth_jwt_module);
	}else{
		conf = (auth_jwt_config_rec *) config;
	}

	switch ((jwt_directive) cmd->info) {
		case dir_signature_algorithm:
			conf->signature_algorithm = value;
			conf->signature_algorithm_set = 1;
		break;
		case dir_signature_shared_secret:
			conf->signature_shared_secret = value;
			conf->signature_shared_secret_set = 1;
		break;
		case dir_signature_public_key_file:
			conf->signature_public_key_file = value;
			conf->signature_public_key_file_set = 1;
		break;
		case dir_signature_private_key_file:
			conf->signature_private_key_file = value;
			conf->signature_private_key_file_set = 1;
		break;
		case dir_iss:
			conf->iss = value;
			conf->iss_set = 1;
		break;
		case dir_aud:
			conf->aud = value;
			conf->aud_set = 1;
		break;
		case dir_form_username:
			conf->form_username = value;
			conf->form_username_set = 1;
		break;
		case dir_form_password:
			conf->form_password = value;
			conf->form_password_set = 1;
		break;
		case dir_attribute_username:
			conf->attribute_username = value;
			conf->attribute_username_set = 1;
		break;
	}

	return NULL;
}

static const char *set_jwt_int_param(cmd_parms * cmd, void* config, const char* value){

	auth_jwt_config_rec *conf;
	if(!cmd->path){
		conf = (auth_jwt_config_rec *) ap_get_module_config(cmd->server->module_config, &auth_jwt_module);
	}else{
		conf = (auth_jwt_config_rec *) config;
	}

	const char *digit;
	for (digit = value; *digit; ++digit) {
		if (!apr_isdigit(*digit)) {
			return "Argument must be numeric!";
		}
	}

	switch ((long) cmd->info) {
		case dir_exp_delay:
			conf->exp_delay = atoi(value);
			conf->exp_delay_set = 1;
		break;
		case dir_nbf_delay:
			conf->nbf_delay = atoi(value);
			conf->nbf_delay_set = 1;
		break;
		case dir_leeway:
			conf->leeway = atoi(value);
			conf->leeway_set = 1;
		break;
	}
	return NULL;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  AUTHZ HANDLERS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

static const char *jwt_parse_config(cmd_parms *cmd, const char *require_line, const void **parsed_require_line){
	const char *expr_err = NULL;
	ap_expr_info_t *expr;
	
	expr = ap_expr_parse_cmd(cmd, require_line, AP_EXPR_FLAG_STRING_RESULT, &expr_err, NULL);
	if(expr_err)
		return apr_pstrcat(cmd->temp_pool, "Cannot parse expression in require line: ", expr_err, NULL);
	
	*parsed_require_line = expr;
	return NULL;
}

static authz_status jwtclaim_check_authorization(request_rec *r, const char* require_args, const void *parsed_require_args){
	ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(55100)
					"auth_jwt require jwt-claim: checking authorization...");
	if(!r->user){
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55101)
					"auth_jwt authorize: no user found...");
		return AUTHZ_DENIED_NO_USER;
	}
	const char* err = NULL;
	const ap_expr_info_t *expr = parsed_require_args;
	const char* require = ap_expr_str_exec(r, expr, &err);
	if(err){
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55102)
		"auth_jwt authorize: require jwt-claim: Can't evaluate expression: %s",err);
		return AUTHZ_DENIED;
	}

	char *w, *value;

	while(require[0]){
		w = ap_getword(r->pool, &require, '=');
		value = ap_getword_conf(r->pool, &require);
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55103)
						"auth_jwt authorize: checking claim %s has value %s", w, value);
		const char* real_value = token_get_claim((jwt_t*)apr_table_get(r->notes, "jwt"), w);
		if(real_value != NULL && apr_strnatcasecmp((const char*)real_value, (const char*)value) == 0){
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55104)
						"auth_jwt authorize: require jwt-claim: authorization successful for claim %s=%s", w, value);
			return AUTHZ_GRANTED;
		}else{
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55105)
						"auth_jwt authorize: require jwt-claim: authorization failed for claim %s=%s", w, value);
		}
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55106)
							"auth_jwt authorize: require jwt-claim: authorization failed");
	
	return AUTHZ_DENIED;
}

static authz_status jwtclaimarray_check_authorization(request_rec *r, const char* require_args, const void *parsed_require_args){
	ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(55107)
					"auth_jwt require jwt-claim-array: checking authorization...");
	if(!r->user){
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55108)
					"auth_jwt authorize: no user found...");
		return AUTHZ_DENIED_NO_USER;
	}
	const char* err = NULL;
	const ap_expr_info_t *expr = parsed_require_args;
	const char* require = ap_expr_str_exec(r, expr, &err);
	if(err){
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55109)
		"auth_jwt authorize: require jwt-claim: Can't evaluate expression: %s",err);
		return AUTHZ_DENIED;
	}

	char *w, *value;

	jwt_t* jwt = (jwt_t*)apr_table_get(r->notes, "jwt");
	if(jwt == NULL){
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	while(require[0]){
		w = ap_getword(r->pool, &require, '=');
		value = ap_getword_conf(r->pool, &require);
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55110)
						"auth_jwt authorize: checking claim %s has value %s", w, value);
		int len;
		char** array_values = token_get_claim_array_of_string(r, jwt, w, &len);
		if(array_values != NULL){
			int i;
			for(i=0;i<len;i++){
				if(apr_strnatcasecmp((const char*)array_values[i], (const char*)value) == 0){
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55111)
						"auth_jwt authorize: require jwt-claim-array: authorization successful for claim %s=%s", w, value);
					return AUTHZ_GRANTED;
				}else{
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55112)
								"auth_jwt authorize: require jwt-claim-array: authorization failed for claim %s=%s", w, value);
				}
			}
		}
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55113)
							"auth_jwt authorize: require jwt-claim: authorization failed");
	
	return AUTHZ_DENIED;
}


/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  AUTHENTICATION HANDLERS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  */


static int auth_jwt_login_handler(request_rec *r){

	if(!r->handler || strcmp(r->handler, JWT_LOGIN_HANDLER)){
		return DECLINED;
	}

	ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(55200)
							"auth_jwt authn: authentication handler is handling authentication");

 	int res;
 	char* buffer;
 	apr_off_t len;
 	apr_size_t size;
 	int rv;

	if(r->method_number != M_POST){
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55201)
		"auth_jwt authn: the " JWT_LOGIN_HANDLER " only supports the POST method for %s", r->uri);
	 	return HTTP_METHOD_NOT_ALLOWED;
 	}

        const char* content_type = apr_table_get(r->headers_in, "Content-Type");
        if(!content_type || strcmp(content_type, "application/x-www-form-urlencoded")!=0){
            	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55202)
                                                        "auth_jwt authn: content type must be x-www-form-urlencoded");
		return HTTP_UNSUPPORTED_MEDIA_TYPE;
        }

 	apr_array_header_t *pairs = NULL;
 	res = ap_parse_form_data(r, NULL, &pairs, -1, FORM_SIZE);
 	if (res != OK) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55202)
							"auth_jwt authn: an error occured while parsing form data, aborting authentication");
		return res;
 	}

 	char* fields[] = {(char *)get_config_value(r, dir_form_username), (char *)get_config_value(r, dir_form_password)};

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55203)
							"auth_jwt authn: reading fields %s and %s", fields[0], fields[1]);

 	char* sent_values[2];

	int i;
	while (pairs && !apr_is_empty_array(pairs)) {
		ap_form_pair_t *pair = (ap_form_pair_t *) apr_array_pop(pairs);
		for(i=0;i<2;i++){
			if (fields[i] && !strcmp(pair->name, fields[i]) && &sent_values[i]) {
				apr_brigade_length(pair->value, 1, &len);
				size = (apr_size_t) len;
				buffer = apr_palloc(r->pool, size + 1);
				apr_brigade_flatten(pair->value, buffer, &size);
				buffer[len] = 0;
				sent_values[i] = buffer;
			}
		}
 	}

	for(i=0;i<2;i++){
		if(!sent_values[i]){
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55204)
								"auth_jwt authn: the expected parameter %s is missing, aborting authentication", fields[i]);
			return HTTP_UNAUTHORIZED;
		}
	}

	r->user = sent_values[USER_INDEX];

	rv = check_authn(r, sent_values[USER_INDEX], sent_values[PASSWORD_INDEX]);

	if(rv == OK){
		char* token;
		rv = create_token(r, &token, sent_values[USER_INDEX]);
		if(rv == OK){
			apr_table_setn(r->err_headers_out, "Content-Type", "application/json");
			ap_rprintf(r, "{\"token\":\"%s\"}", token);
			free(token);
		}
	}

	return rv;
}


static int create_token(request_rec *r, char** token_str, const char* username){
	
	ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(55300)
							"auth_jwt: creating token...");

	jwt_t *token;
	int allocate = token_new(&token);
	if(allocate!=0){
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55301)
							"auth_jwt create_token: error while creating token: %s", strerror(errno));
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
	char* signature_algorithm = (char *)get_config_value(r, dir_signature_algorithm);
	unsigned char sign_key[MAX_KEY_LEN] = { 0 };
    unsigned int keylen;
	get_encode_key(r, signature_algorithm, sign_key, &keylen);

	if(keylen == 0){
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55302)
							"auth_jwt create_token: key used for signature is empty");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	char* iss = (char *)get_config_value(r, dir_iss);
	char* aud = (char *)get_config_value(r, dir_aud);
	int exp_delay = get_config_int_value(r, dir_exp_delay);
	int nbf_delay = get_config_int_value(r, dir_nbf_delay);

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55305)
							"auth_jwt create_token: using algorithm %s (key length=%d)...", signature_algorithm, keylen);

	if(token_set_alg(r, token, signature_algorithm, sign_key, keylen)!=0){
        return HTTP_INTERNAL_SERVER_ERROR;
    }
	

	time_t now = time(NULL);
	time_t iat = now;
	time_t exp = now;
	time_t nbf = now;


	if(exp_delay >= 0){
		exp += exp_delay;
		token_add_claim_int(token, "exp", (long)exp);
	}

	if(nbf_delay >= 0){
		nbf += nbf_delay;
		token_add_claim_int(token, "nbf", (long)nbf);
	}

	token_add_claim_int(token, "iat", (long)iat);

	if(iss){
		token_add_claim(token, "iss", iss);
	}

	if(aud){
		token_add_claim(token, "aud", aud);
	}

	const char* username_attribute = (const char *)get_config_value(r, dir_attribute_username);

	token_add_claim(token, username_attribute, username);

	*token_str = token_encode_str(token);
	token_free(token);
	return OK;
}

static int check_authn(request_rec *r, const char *username, const char *password){
	ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(55220)
							"auth_jwt: authenticating user");
	authn_status authn_result;
	authn_provider_list *current_provider;
	auth_jwt_config_rec *conf = ap_get_module_config(r->per_dir_config, &auth_jwt_module);

	current_provider = conf->providers;
	do {
		const authn_provider *provider;

		if (!current_provider) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55221)
						  "no authn provider configured");
			authn_result = AUTH_GENERAL_ERROR;
			break;
		}
		else {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55222)
							"auth_jwt authn: using provider %s", current_provider->provider_name);
			provider = current_provider->provider;
			apr_table_setn(r->notes, AUTHN_PROVIDER_NAME_NOTE, current_provider->provider_name);
		}

		if (!username || !password) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55223)
							"auth_jwt authn: username or password is missing, cannot pursue authentication");
			authn_result = AUTH_USER_NOT_FOUND;
			break;
		}

		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55224)
							"auth_jwt authn: checking credentials...");
		authn_result = provider->check_password(r, username, password);

		apr_table_unset(r->notes, AUTHN_PROVIDER_NAME_NOTE);

		if (authn_result != AUTH_USER_NOT_FOUND) {
			break;
		}

		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55225)
							"auth_jwt authn: no user has been found, trying the next provider...");

		if (!conf->providers) {
			break;
		}

		current_provider = current_provider->next;
	} while (current_provider);

	if (authn_result != AUTH_GRANTED) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55226)
							"auth_jwt authn: credentials are not correct");
		int return_code;

		/*if (authn_result != AUTH_DENIED) && !(conf->authoritative))
			return DECLINED;
		}*/

		switch (authn_result) {
		  	case AUTH_DENIED:
			  	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55227)
							"user '%s': authentication failure for \"%s\": "
							"password Mismatch",
							username, r->uri);
				return_code = HTTP_UNAUTHORIZED;
			  	break;
		  	case AUTH_USER_NOT_FOUND:
			  	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55228)
							"user '%s' not found: %s", username, r->uri);
			  	return_code = HTTP_UNAUTHORIZED;
			  	break;
		  	case AUTH_GENERAL_ERROR:
		  	default:
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55229)
							"auth_jwt authn: an error occured in the authentication provider, aborting authentication");
			  	return_code = HTTP_INTERNAL_SERVER_ERROR;
			  	break;
		}
		
		return return_code;
	}
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55230)
							"auth_jwt authn: credentials are correct");
	return OK;
}


/*
If we are configured to handle authentication, let's look up headers to find
whether or not 'Authorization' is set. If so, exepected format is
Authorization: Bearer json_web_token. Then we check if the token is valid.
*/
static int auth_jwt_authn_with_token(request_rec *r){
	const char *current_auth = NULL;
	current_auth = ap_auth_type(r);
	int rv;

	if (!current_auth || strcmp(current_auth, "jwt")) {
		return DECLINED;
	}

	ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(55400)
							"auth_jwt: checking authentication with token...");

	/* We need an authentication realm. */
	if (!ap_auth_name(r)) {
	   	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55401)
					 "need AuthName: %s", r->uri);
	   	return HTTP_INTERNAL_SERVER_ERROR;
	}

	r->ap_auth_type = (char *) current_auth;

	ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(55402)
							"auth_jwt authn: reading Authorization header...");
	char* authorization_header = (char*)apr_table_get( r->headers_in, "Authorization");
	char* token_str;
	
	unsigned char key[MAX_KEY_LEN] = { 0 };
	unsigned int keylen;

	get_decode_key(r, key, &keylen);

	if(keylen == 0){
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55403)
							"auth_jwt authn: key used to check signature is empty");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if(!authorization_header){
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55404)
							"auth_jwt authn: missing Authorization header, responding with WWW-Authenticate header...");
		apr_table_setn(r->err_headers_out, "WWW-Authenticate", apr_pstrcat(r->pool, "Bearer realm=\"", ap_auth_name(r),"\"", NULL));
		return HTTP_UNAUTHORIZED;
	}

	int header_len = strlen(authorization_header);
	if(header_len > 7 && !strncmp(authorization_header, "Bearer ", 7)){
		token_str = authorization_header+7;
		jwt_t* token;
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55405)
							"auth_jwt authn: checking signature and fields correctness...");
		rv = token_check(r, &token, token_str, key, keylen);
        
		if(OK == rv){
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55406)
							"auth_jwt authn: signature is correct");
            const char* found_alg = token_get_alg(token);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(55405)
							"auth_jwt authn: algorithm found is %s", found_alg);
			const char* attribute_username = (const char*)get_config_value(r, dir_attribute_username);
			char* maybe_user = (char *)token_get_claim(token, attribute_username);
			if(maybe_user == NULL){
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55407)
						"Username was not in token ('%s' attribute is expected)", attribute_username);
				apr_table_setn(r->err_headers_out, "WWW-Authenticate", apr_pstrcat(r->pool,
				"Bearer realm=\"", ap_auth_name(r),"\", error=\"invalid_token\", error_description=\"Username was not in token\"",
				 NULL));
				return HTTP_UNAUTHORIZED;
			}
			apr_table_setn(r->notes, "jwt", (const char*)token);		
			r->user = maybe_user;
			return OK;
		}else{
			return rv;
		}

		if(token)
			token_free(token);
	}else{
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55408)
							"auth_jwt authn: type of Authorization header is not Bearer");
		apr_table_setn(r->err_headers_out, "WWW-Authenticate", apr_pstrcat(r->pool,
		"Bearer realm=\"", ap_auth_name(r),"\", error=\"invalid_request\", error_description=\"Authentication type must be Bearer\"",
		 NULL));
		return HTTP_UNAUTHORIZED;
	}
}


/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  TOKEN OPERATIONS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  */

static void get_encode_key(request_rec *r, const char* signature_algorithm, unsigned char* key, unsigned int* keylen){

	if(strcmp(signature_algorithm, "HS512")==0 || strcmp(signature_algorithm, "HS384")==0 || strcmp(signature_algorithm, "HS256")==0){
		char* signature_shared_secret = (char*)get_config_value(r, dir_signature_shared_secret);
		if(!signature_shared_secret){
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55501)
					 "You must specify AuthJWTSignatureSharedSecret directive in configuration with algorithm %s", signature_algorithm);
			return;
		}
		apr_pool_t *base64_decode_pool;
		apr_pool_create(&base64_decode_pool, NULL);
		int decoded_len = apr_base64_decode_len((const char*)signature_shared_secret);
		char *decode_buf = apr_palloc(base64_decode_pool, decoded_len);
		apr_base64_decode(decode_buf, signature_shared_secret); /* was bin */
		memcpy((char*)key, (const char*)decode_buf, (size_t)decoded_len);
        *keylen = decoded_len;
	}
	else if(strcmp(signature_algorithm, "RS512")==0 || strcmp(signature_algorithm, "RS384")==0 || strcmp(signature_algorithm, "RS256")==0 ||
			strcmp(signature_algorithm, "ES512")==0 || strcmp(signature_algorithm, "ES384")==0 || strcmp(signature_algorithm, "ES256")==0){
		char* signature_private_key_file = (char*)get_config_value(r, dir_signature_private_key_file);
		if(!signature_private_key_file){
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55502)
					 "You must specify AuthJWTSignaturePrivateKeyFile directive in configuration with algorithm %s", signature_algorithm);
			return;
		}
		apr_status_t rv;
		apr_file_t* key_fd = NULL;
		rv = apr_file_open(&key_fd, signature_private_key_file, APR_READ, APR_OS_DEFAULT, r->pool);
		if(rv!=APR_SUCCESS){
                        char error_buf[50];
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55503)
					 "Unable to open the file %s: %s", signature_private_key_file, apr_strerror(rv, error_buf, 50));
			return;
		}
		apr_size_t key_len;
		rv = apr_file_read_full(key_fd, key, MAX_KEY_LEN, &key_len); 
		if(rv!=APR_SUCCESS && rv!=APR_EOF){
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55504)
					"Error while reading the file %s", signature_private_key_file);
			return;
		}
		apr_file_close(key_fd);
        *keylen = (unsigned int)key_len;
	} else {
		//unknown algorithm
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55505)
					"Unknown algorithm %s", signature_algorithm);
	}
}

static void get_decode_key(request_rec *r, unsigned char* key, unsigned int* keylen){
    char* signature_public_key_file = (char*)get_config_value(r, dir_signature_public_key_file);
    char* signature_shared_secret = (char*)get_config_value(r, dir_signature_shared_secret);

	if(!signature_shared_secret && !signature_public_key_file){
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55507)
				"You must specify either AuthJWTSignatureSharedSecret directive or AuthJWTSignaturePublicKeyFile directive in configuration for decoding process");
		return;
    }

    if(signature_shared_secret && signature_public_key_file){
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55507)
				"Conflict in configuration: you must specify either AuthJWTSignatureSharedSecret directive or AuthJWTSignaturePublicKeyFile directive but not both in the same block");
		return;
    }

    if(signature_shared_secret){
        apr_pool_t *base64_decode_pool;
        apr_pool_create(&base64_decode_pool, NULL);
		int decode_len = apr_base64_decode_len((const char*)signature_shared_secret);
        char *decode_buf = apr_palloc(base64_decode_pool, decode_len);
        apr_base64_decode(decode_buf, signature_shared_secret); 
        memcpy((char*)key, (const char*)decode_buf, decode_len);
		*keylen = (unsigned int)decode_len;
    }
    else if(signature_public_key_file){
		apr_status_t rv;
		apr_file_t* key_fd = NULL;
		rv = apr_file_open(&key_fd, signature_public_key_file, APR_FOPEN_READ, APR_FPROT_OS_DEFAULT, r->pool);
		if(rv!=APR_SUCCESS){
                        char error_buf[50];
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55503)
                                         "Unable to open the file %s: %s", signature_public_key_file, apr_strerror(rv, error_buf, 50));
                        return;
		}
		apr_size_t key_len;
		rv = apr_file_read_full(key_fd, key, MAX_KEY_LEN, &key_len); 
		if(rv!=APR_SUCCESS && rv!=APR_EOF){
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55510)
					"Error while reading the file %s", signature_public_key_file);
			return;
		}
		*keylen = (unsigned int)key_len;
		apr_file_close(key_fd);
    }
}

static int token_new(jwt_t **jwt){
 	return jwt_new(jwt);
}


static int token_check(request_rec *r, jwt_t **jwt, const char *token, const unsigned char *key, unsigned int keylen){

	int decode_res = token_decode(jwt, token, key, keylen);

	if(decode_res != 0){
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55512)"Decoding process has failed, token is either malformed or signature is invalid");
		apr_table_setn(r->err_headers_out, "WWW-Authenticate", apr_pstrcat(r->pool,
		"Bearer realm=\"", ap_auth_name(r),"\", error=\"invalid_token\", error_description=\"Token is malformed or signature is invalid\"",
		NULL));
		return HTTP_UNAUTHORIZED;
	}

	/*
	Trunk of libjwt does not need this check because the bug is fixed
	We should not accept token with provided alg none
	*/
	if(*jwt && jwt_get_alg(*jwt) == JWT_ALG_NONE){
		apr_table_setn(r->err_headers_out, "WWW-Authenticate", apr_pstrcat(r->pool,
		"Bearer realm=\"", ap_auth_name(r),"\", error=\"invalid_token\", error_description=\"Token is malformed\"",
		NULL));
		return HTTP_UNAUTHORIZED;
	}

	/*
	Do not accept other signature algorithms than configured
	*/
	const char* sig_config = (char *)get_config_value(r, dir_signature_algorithm);
	if(*jwt && parse_alg(sig_config) != jwt_get_alg(*jwt)){
		apr_table_setn(r->err_headers_out, "WWW-Authenticate", apr_pstrcat(r->pool,
		"Bearer realm=\"", ap_auth_name(r),"\", error=\"invalid_token\", error_description=\"Unsupported Signature Algorithm\"",
		NULL));
		return HTTP_UNAUTHORIZED;
	}

	const char* iss_config = (char *)get_config_value(r, dir_iss);
	const char* aud_config = (char *)get_config_value(r, dir_aud);
	int leeway = get_config_int_value(r, dir_leeway);

	const char* iss_to_check = token_get_claim(*jwt, "iss");
	if(iss_config && iss_to_check && strcmp(iss_config, iss_to_check)!=0){
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55513)"Token issuer does not match with configured issuer");
		apr_table_setn(r->err_headers_out, "WWW-Authenticate", apr_pstrcat(r->pool,
		"Bearer realm=\"", ap_auth_name(r),"\", error=\"invalid_token\", error_description=\"Issuer is not valid\"",
		NULL));
		return HTTP_UNAUTHORIZED;
	}

	const char* aud_to_check = token_get_claim(*jwt, "aud");
	if(aud_config && aud_to_check && strcmp(aud_config, aud_to_check)!=0){
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55514)"Token audience does not match with configured audience");
		apr_table_setn(r->err_headers_out, "WWW-Authenticate", apr_pstrcat(r->pool,
		"Bearer realm=\"", ap_auth_name(r),"\", error=\"invalid_token\", error_description=\"Audience is not valid\"",
		NULL));
		return HTTP_UNAUTHORIZED;
	}

	/* check exp */
	long exp = token_get_claim_int(*jwt, "exp");
	if(exp>0){
		time_t now = time(NULL);
		if (exp + leeway < now){
			/* token expired */
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55516)"Token expired");
			apr_table_setn(r->err_headers_out, "WWW-Authenticate", apr_pstrcat(r->pool,
			"Bearer realm=\"", ap_auth_name(r),"\", error=\"invalid_token\", error_description=\"Token expired\"",
			NULL));
			return HTTP_UNAUTHORIZED;
		}
	}else{
		/* exp is mandatory parameter */
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55517)"Missing exp in token");
		apr_table_setn(r->err_headers_out, "WWW-Authenticate", apr_pstrcat(r->pool,
		"Bearer realm=\"", ap_auth_name(r),"\", error=\"invalid_token\", error_description=\"Expiration is missing in token\"",
		NULL));
		return HTTP_UNAUTHORIZED;
	}

	/* check nbf */
	long nbf = token_get_claim_int(*jwt, "nbf");
	if(nbf>0){
		time_t now = time(NULL);
		if (nbf - leeway > now){
			/* token is too recent to be processed */
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55518)"Nbf check failed. Token can't be processed now");
			apr_table_setn(r->err_headers_out, "WWW-Authenticate", apr_pstrcat(r->pool,
			"Bearer realm=\"", ap_auth_name(r),"\", error=\"invalid_token\", error_description=\"Token can't be processed now due to nbf field\"",
			NULL));
			return HTTP_UNAUTHORIZED;
		}
	}
	return OK;
}

static int token_decode(jwt_t **jwt, const char* token, const unsigned char *key, unsigned int keylen){
	return jwt_decode(jwt, token, key, keylen);
}

static char *token_encode_str(jwt_t *jwt){
	return jwt_encode_str(jwt);
}

static int token_add_claim(jwt_t *jwt, const char *claim, const char *val){
	return jwt_add_grant(jwt, claim, val);
}

static int token_add_claim_int(jwt_t *jwt, const char *claim, long val){
	return jwt_add_grant_int(jwt, claim, val);
}

static const char* token_get_claim(jwt_t *token, const char* claim){
	return jwt_get_grant(token, claim);
}

static long token_get_claim_int(jwt_t *token, const char* claim){
	return jwt_get_grant_int(token, claim);
}


static char** token_get_claim_array_of_string(request_rec *r, jwt_t *token, const char* claim, int* len){
	json_t* array = token_get_claim_array(r, token, claim);
	if(!array){
		return NULL;
	}

	int array_len = json_array_size(array);
	char** values = (char**)apr_pcalloc(r->pool, array_len*sizeof(char*));
	int i;
	for(i=0; i<array_len; i++){
		json_t* data;
		data = json_array_get(array, i);
		if(!json_is_string(data)){
			json_decref(array);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55519)"Claim '%s' is not an array of", claim);
			return NULL;
		}
		const char* string_value = (const char*)json_string_value(data);
		values[i] = (char*)apr_pcalloc(r->pool, strlen(string_value)+1*sizeof(char));
		strcpy(values[i], string_value);
	}
	json_decref(array);
	*len = array_len;
	return values;
}

static json_t* token_get_claim_array(request_rec *r, jwt_t *token, const char* claim){
	json_t* array = token_get_claim_json(r, token, claim);
	
	if(!array){
		return NULL;
	}

	if(!json_is_array(array)){
		json_decref(array);
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55520)"Claim '%s' is not a JSON array", claim);
		return NULL;
	}
	return array;
}

static json_t* token_get_claim_json(request_rec *r, jwt_t *token, const char* claim){
	char* json_str = jwt_get_grants_json(token, claim);
	if(json_str == NULL){
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55521)"Missing claim '%s' in token", claim);
		return NULL;
	}
	json_error_t error;
	json_t* json = json_loads(json_str, 0, &error);

	if(!json){
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55522)"Claim '%s' is not a JSON valid string: %s", claim, error.text);
		return NULL;
	}

	return json;
}

static int token_set_alg(request_rec *r, jwt_t *jwt, const char* signature_algorithm, const unsigned char *key, unsigned int keylen){
	jwt_alg_t algorithm;
	if(!strcmp(signature_algorithm, "HS512")){
		algorithm = JWT_ALG_HS512;
	}else if(!strcmp(signature_algorithm, "HS384")){
		algorithm = JWT_ALG_HS384;
	}else if(!strcmp(signature_algorithm, "HS256")){
		algorithm = JWT_ALG_HS256;
	}else if(!strcmp(signature_algorithm, "RS512")){
		algorithm = JWT_ALG_RS512;
	}else if(!strcmp(signature_algorithm, "RS384")){
		algorithm = JWT_ALG_RS384;
	}else if(!strcmp(signature_algorithm, "RS256")){
		algorithm = JWT_ALG_RS256;
	}else if(!strcmp(signature_algorithm, "ES512")){
		algorithm = JWT_ALG_ES512;
	}else if(!strcmp(signature_algorithm, "ES384")){
		algorithm = JWT_ALG_ES384;
	}else if(!strcmp(signature_algorithm, "ES256")){
		algorithm = JWT_ALG_ES256;
	}else{
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(55304)
				  "Unknown algorithm %s", signature_algorithm);
		return 1;
	}
	return jwt_set_alg(jwt, algorithm, key, keylen);
}

static const char* token_get_alg(jwt_t *jwt){
	jwt_alg_t algorithm = jwt_get_alg(jwt);
    switch(algorithm){
        case JWT_ALG_HS256:
            return "HS256";
        case JWT_ALG_HS384:
            return "HS384";
        case JWT_ALG_HS512:
            return "HS512";
        case JWT_ALG_RS256:
            return "RS256";
        case JWT_ALG_RS384:
            return "RS384";
        case JWT_ALG_RS512:
            return "RS512";
        case JWT_ALG_ES256:
            return "ES256";
        case JWT_ALG_ES384:
            return "ES384";
        case JWT_ALG_ES512:
            return "ES512";
        default:
            return NULL;
    }
}

static jwt_alg_t parse_alg(const char* signature_algorithm) {
	jwt_alg_t algorithm;
	if(!strcmp(signature_algorithm, "HS512")){
		algorithm = JWT_ALG_HS512;
	}else if(!strcmp(signature_algorithm, "HS384")){
		algorithm = JWT_ALG_HS384;
	}else if(!strcmp(signature_algorithm, "HS256")){
		algorithm = JWT_ALG_HS256;
	}else if(!strcmp(signature_algorithm, "RS512")){
		algorithm = JWT_ALG_RS512;
	}else if(!strcmp(signature_algorithm, "RS384")){
		algorithm = JWT_ALG_RS384;
	}else if(!strcmp(signature_algorithm, "RS256")){
		algorithm = JWT_ALG_RS256;
	}else if(!strcmp(signature_algorithm, "ES512")){
		algorithm = JWT_ALG_ES512;
	}else if(!strcmp(signature_algorithm, "ES384")){
		algorithm = JWT_ALG_ES384;
	}else if(!strcmp(signature_algorithm, "ES256")){
		algorithm = JWT_ALG_ES256;
	}else{
		algorithm = JWT_ALG_NONE;
	}
	return algorithm;
}

static void token_free(jwt_t *token){
	jwt_free(token);
}

