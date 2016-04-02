
#include <stdio.h>
#include <stdlib.h>

// RFC 7519 compliant library
#include <jwt.h>


#include "apr_strings.h"
#include "apr_lib.h"                /* for apr_isspace */
#include "apr_base64.h"             /* for apr_base64_decode et al */
#define APR_WANT_STRFUNC            /* for strcasecmp */
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_provider.h"
#include "util_md5.h"
#include "ap_expr.h"

#include "mod_auth.h"
#include "mod_session.h"
#include "mod_request.h"

#define JWT_LOGIN_HANDLER "jwt-login-handler"
#define JWT_LOGOUT_HANDLER "jwt-login-handler"
#define USER_INDEX 0
#define PASSWORD_INDEX 1

typedef struct {
    authn_provider_list *providers;

    const char* signature_algorithm;
    int signature_algorithm_set;

    const char* signature_secret;
    int signature_secret_set;

    char *dir;
    int authoritative;
    int authoritative_set;

    apr_size_t form_size;
    int form_size_set;
} auth_jwt_config_rec;


static const char *add_authn_provider(cmd_parms * cmd, void *config, const char *arg);
static void *create_auth_jwt_dir_config(apr_pool_t *p, char *d);
//static void *create_auth_jwt_config(apr_pool_t * p, server_rec *s);
static int auth_jwt_login_handler(request_rec *r);
static void register_hooks(apr_pool_t * p);
static int perform_jwt_authn(request_rec *r);

static int auth_jwt_post_perdir_config(request_rec *r);
static int create_token(request_rec *r, char** token_str, const char* username);
static int check_authn(request_rec *r, const char *username, const char *password);

static const char *set_signature_algorithm(cmd_parms * cmd, void* config, const char* signature_algorithm);
static const char *set_signature_secret(cmd_parms * cmd, void* config, const char* secret);

static const command_rec auth_jwt_cmds[] =
{
   AP_INIT_ITERATE("AuthJWTProvider", add_authn_provider, NULL, OR_AUTHCFG,
                    "Specify the auth providers for a directory or location"),
   AP_INIT_TAKE1("AuthJWTSignatureAlgorithm", set_signature_algorithm, NULL, OR_AUTHCFG,
                    "The algorithm to use to sign tokens"),
   AP_INIT_TAKE1("AuthJWTSignatureSecret", set_signature_secret, NULL, OR_AUTHCFG,
                     "The secret to use to sign tokens with HMACs"),
   {NULL}
};

AP_DECLARE_MODULE(auth_jwt) = {
  STANDARD20_MODULE_STUFF,
  create_auth_jwt_dir_config,
  NULL,
  NULL,
  NULL,
  auth_jwt_cmds,
  register_hooks
};


static void register_hooks(apr_pool_t * p){
  ap_hook_handler(auth_jwt_login_handler, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_check_authn(perform_jwt_authn, NULL, NULL, APR_HOOK_MIDDLE,
                        AP_AUTH_INTERNAL_PER_CONF);
  ap_hook_post_perdir_config(auth_jwt_post_perdir_config, NULL, NULL, APR_HOOK_MIDDLE);
}

/*
If we are configured to handle authentication, let's look up headers to find
whether or not 'Authorization' is set. If so, exepected format is
Authorization: Bearer json_web_token. Then we check if the token is valid.
*/
static int perform_jwt_authn(request_rec *r){
  const char *current_auth = NULL;
  current_auth = ap_auth_type(r);

  if (!current_auth || strcmp(current_auth, "jwt")) {
      return DECLINED;
  }

  if (!ap_auth_name(r)) {
       ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01810)
                     "need AuthName: %s", r->uri);
       return HTTP_INTERNAL_SERVER_ERROR;
  }

  r->ap_auth_type = (char *) current_auth;

  char* authorization_header = (char*)apr_table_get( r->headers_in, "Authorization");
  char* token_str;

  auth_jwt_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                    &auth_jwt_module);
  if(!conf->signature_secret_set){
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01810)
                  "You must specify AuthJWTSignatureSecret directive in configuration");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  if(!authorization_header){
    return HTTP_UNAUTHORIZED;
  }
  int decode_res;
  int header_len = strlen(authorization_header);
  if(header_len > 7 && !strncmp(authorization_header, "Bearer ", 7)){
    token_str = authorization_header+7;
    jwt_t* token;
    decode_res = jwt_decode(&token, token_str, conf->signature_secret, 64);
    if(decode_res==0){
      r->user = jwt_get_grant(token, "user");
      return OK;
    }else{
      return HTTP_UNAUTHORIZED;
    }
  }else{
    return HTTP_UNAUTHORIZED;
  }
}

static const char *add_authn_provider(cmd_parms * cmd, void *config,
                                           const char *arg)
{
    auth_jwt_config_rec *conf = (auth_jwt_config_rec *) config;
    authn_provider_list *newp;

    newp = apr_pcalloc(cmd->pool, sizeof(authn_provider_list));
    newp->provider_name = arg;

    newp->provider = ap_lookup_provider(AUTHN_PROVIDER_GROUP,
                                        newp->provider_name,
                                        AUTHN_PROVIDER_VERSION);

    if (newp->provider == NULL) {
        return apr_psprintf(cmd->pool,
                            "Unknown Authn provider: %s",
                            newp->provider_name);
    }

    if (!newp->provider->check_password) {
        return apr_psprintf(cmd->pool,
                            "The '%s' Authn provider doesn't support "
                            "Form Authentication", newp->provider_name);
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

static const char *set_signature_algorithm(cmd_parms * cmd, void* config, const char* signature_algorithm){
  auth_jwt_config_rec *conf = (auth_jwt_config_rec *) config;
  conf->signature_algorithm = signature_algorithm;
  conf->signature_algorithm_set = 1;
  return NULL;
}

static const char *set_signature_secret(cmd_parms * cmd, void* config, const char* signature_secret){
  auth_jwt_config_rec *conf = (auth_jwt_config_rec *) config;
  conf->signature_secret = signature_secret;
  conf->signature_secret_set = 1;
  return NULL;
}

static void *create_auth_jwt_dir_config(apr_pool_t *p, char *d){
  auth_jwt_config_rec *conf = apr_pcalloc(p, sizeof(*conf));
  conf->dir = d;
  conf->authoritative = 1;
  conf->form_size = HUGE_STRING_LEN;
  conf->signature_algorithm = "HS512";
  return conf;
}

/*static void *create_auth_jwt_config(apr_pool_t * p, server_rec *s){

}*/

static int create_token(request_rec *r, char** token_str, const char* username){
  jwt_t *token;
  jwt_alg_t hs512 = JWT_ALG_HS512;

  auth_jwt_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                    &auth_jwt_module);
  if(!conf->signature_secret_set){
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01810)
                  "You must specify AuthJWTSignatureSecret directive in configuration");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  int allocate = jwt_new(&token);

  jwt_set_alg(token, hs512, (unsigned char*)conf->signature_secret, 64);

  time_t now = time(NULL)+1800;
  char timestamp_str[11];
  sprintf(timestamp_str, "%ld", now);
  timestamp_str[10] = '\0';
  jwt_add_grant(token, "iss", "auth.lade.cyberrange.csclab.net");
  jwt_add_grant(token, "aud", "api.lade.cyberrange.csclab.net");
  jwt_add_grant(token, "iat", timestamp_str);
  jwt_add_grant(token, "nbf", timestamp_str);
  jwt_add_grant(token, "exp", timestamp_str);
  jwt_add_grant(token, "user", username);

  *token_str = jwt_encode_str(token);
  jwt_free(token);

  return OK;
}

static int check_authn(request_rec *r, const char *username, const char *password){
    authn_status authn_result;
    authn_provider_list *current_provider;
    auth_jwt_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &auth_jwt_module);

    current_provider = conf->providers;
    do {
        const authn_provider *provider;

        if (!current_provider) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01806)
                          "no authn provider configured");
            authn_result = AUTH_GENERAL_ERROR;
            break;
        }
        else {
            provider = current_provider->provider;
            apr_table_setn(r->notes, AUTHN_PROVIDER_NAME_NOTE, current_provider->provider_name);
        }

        if (!username || !password) {
            authn_result = AUTH_USER_NOT_FOUND;
            break;
        }

        authn_result = provider->check_password(r, username, password);

        apr_table_unset(r->notes, AUTHN_PROVIDER_NAME_NOTE);

        if (authn_result != AUTH_USER_NOT_FOUND) {
            break;
        }

        if (!conf->providers) {
            break;
        }

        current_provider = current_provider->next;
    } while (current_provider);

    if (authn_result != AUTH_GRANTED) {
        int return_code;

        if (!(conf->authoritative) && authn_result != AUTH_DENIED) {
            return DECLINED;
        }

        switch (authn_result) {
          case AUTH_DENIED:
              ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01807)
                            "user '%s': authentication failure for \"%s\": "
                            "password Mismatch",
                            username, r->uri);
              return_code = HTTP_UNAUTHORIZED;
              break;
          case AUTH_USER_NOT_FOUND:
              ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01808)
                            "user '%s' not found: %s", username, r->uri);
              return_code = HTTP_UNAUTHORIZED;
              break;
          case AUTH_GENERAL_ERROR:
          default:
              return_code = HTTP_INTERNAL_SERVER_ERROR;
              break;
        }

        return return_code;
    }

    return OK;
}

static int auth_jwt_login_handler(request_rec *r){

  int res;
  char* buffer;
  apr_off_t len;
  apr_size_t size;
  int rv;

  if(!r->handler || strcmp(r->handler, JWT_LOGIN_HANDLER)){
    return DECLINED;
  }

  if(r->method_number != M_POST){
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01811)
          "the " JWT_LOGIN_HANDLER " only supports the POST method for %s",
                      r->uri);
    return HTTP_METHOD_NOT_ALLOWED;
  }

  apr_array_header_t *pairs = NULL;
  res = ap_parse_form_data(r, NULL, &pairs, -1, 512);
  if (res != OK) {
    return res;
  }
  char* fields_name[] = {"user", "password"};
  char* fields[] = {fields_name[USER_INDEX], fields_name[PASSWORD_INDEX]};

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
      return HTTP_BAD_REQUEST;
    }
  }

  r->user = sent_values[USER_INDEX];

  rv = check_authn(r, sent_values[USER_INDEX], sent_values[PASSWORD_INDEX]);

  if(rv == OK){
    char* token;
    rv = create_token(r, &token, sent_values[USER_INDEX]);
    if(rv == OK){
      ap_rprintf(r, "%s ", token);
      free(token);
    }
  }

  return rv;
}

static int auth_jwt_post_perdir_config(request_rec *r){

  auth_jwt_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                    &auth_jwt_module);
  return OK;
}
