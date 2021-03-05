# mod_authnz_jwt

Authentication module for Apache httpd with JSON web tokens (JWT).

[![Build Status](https://travis-ci.org/AnthonyDeroche/mod_authnz_jwt.svg?branch=master)](https://travis-ci.org/AnthonyDeroche/mod_authnz_jwt)

More on JWT : https://jwt.io/

Supported algorithms : HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512

Built-in checks : iss, aud, exp, nbf

Configurable checks : every claims contained in the token (only string and array)

This module is able to deliver JSON web tokens containing all public fields (iss, aud, sub, iat, nbf, exp), and the private field "user". Authentication process is carried out by an authentication provider and specified by the AuthJWTProvider directive.

On the other hand, this module is able to check validity of token based on its signature, and on its public fields. If the token is valid, then the user is authenticated and can be used by an authorization provider with the directive "Require valid-user" to authorize or not the request.

Although this module is able to deliver valid tokens, it may be used to check tokens delivered by a custom application in any language, as long as a secret is shared between the two parts. This feature is possible because token-based authentication is stateless.

## Build Requirements

- libjwt (https://github.com/benmcollins/libjwt)
- Apache development package (apache2-dev on Debian/Ubuntu and httpd-devel on CentOS/Fedora)

## Quick start


### Installation using Docker

See [Dockerfile](https://github.com/AnthonyDeroche/mod_authnz_jwt/blob/master/docker/Dockerfile)


### Installation from sources
~~~~
sudo apt-get install libtool pkg-config autoconf libssl-dev check libjansson-dev
git clone https://github.com/benmcollins/libjwt
cd libjwt
git checkout tags/v1.12.1
autoreconf -i
./configure
make
sudo make install
cd ..
sudo apt-get install apache2 apache2-dev libz-dev
git clone https://github.com/AnthonyDeroche/mod_authnz_jwt
cd mod_authnz_jwt
autoreconf -ivf
./configure
make
sudo make install
~~~~

### Generate EC keys
~~~~
openssl ecparam -name secp256k1 -genkey -noout -out ec-priv.pem
openssl ec -in ec-priv.pem -pubout -out ec-pub.pem
~~~~

### Generate RSA keys
~~~~
openssl genpkey -algorithm RSA -out rsa-priv.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout -in rsa-priv.pem -out rsa-pub.pem
~~~~

### Authentication

The common workflow is to authenticate against a token service using for instance username/password. Then we reuse this token to authenticate our next requests as long as the token remains valid.

#### Using username/password

You can configure the module to deliver a JWT if your username/password is correct. Use "AuthJWTProvider" to configure which providers will be used to authenticate the user. 

Authentication modules are for instance: 
- mod_authn_file        (https://httpd.apache.org/docs/2.4/mod/mod_authn_file.html)
- mod_authn_dbd         (https://httpd.apache.org/docs/2.4/mod/mod_authn_dbd.html)
- mod_authn_dbm         (https://httpd.apache.org/docs/2.4/mod/mod_authn_dbm.html)
- mod_authn_socache     (https://httpd.apache.org/docs/2.4/mod/mod_authn_socache.html)
- mod_authnz_ldap       (https://httpd.apache.org/docs/2.4/mod/mod_authnz_ldap.html)
- mod_authnz_fcgi       (https://httpd.apache.org/docs/2.4/mod/mod_authnz_fcgi.html)
- mod_authnz_external   (https://code.google.com/archive/p/mod-auth-external/)
- mod_authn_anon        (https://httpd.apache.org/docs/2.4/mod/mod_authn_anon.html)

The delivered token will contain your username in a field named "user" (See AuthJWTAttributeUsername to override this value) as well as public fields exp, iat, nbf and possibly iss and aud according to the configuration.

A minimal configuration might be:
~~~~
AuthJWTSignatureAlgorithm HS256
AuthJWTSignatureSharedSecret Q0hBTkdFTUU=
AuthJWTIss example.com
<Location /demo/login>
	SetHandler jwt-login-handler
	AuthJWTProvider file
	AuthUserFile /var/www/jwt.htpasswd
</Location>
~~~~

#### Using a JWT

A secured area can be accessed if the provided JWT is valid. JWT must be set in Authorization header. Its value must be "Bearer <jwt>".

If the signature is correct and fields are correct, then a secured location can be accessed.

Token must not be expired (exp), not processed too early (nbf), and issuer/audience must match the configuration.

A minimal configuration might be:
~~~~
AuthJWTSignatureAlgorithm HS256
AuthJWTSignatureSharedSecret Q0hBTkdFTUU=
AuthJWTIss example.com
<Directory /var/www/html/demo/secured/>
	AllowOverride None
	AuthType jwt
	AuthName "private area"
	Require valid-user
</Directory>
~~~~


### Authorization

You can use the directive Require jwt-claim key1=value1 key2=value2. Putting multiple keys/values in the same require results in an OR. You can use RequireAny and RequireAll directives to be more precise in your rules. 

In case your key is an array, you can use the directive Require jwt-claim-array key1=value1 to test that "value1" is contained in the array pointed by the key "key1".

Examples:
~~~~
AuthJWTSignatureAlgorithm HS256
AuthJWTSignatureSharedSecret Q0hBTkdFTUU=
AuthJWTIss example.com
<Directory /var/www/html/demo/secured/>
	AllowOverride None
	AuthType jwt
	AuthName "private area"
	Require jwt-claim user=toto
    Require jwt-claim-array groups=group1
</Directory>
~~~~

### How to get authenticated user in your apps?
If your app is directly hosted by the same Apache than the module, then you can read the environment variable "REMOTE_USER".

If the apache instance on which the module is installed acts as a reverse proxy, then you need to add a header in the request (X-Remote-User for example). We use mod_rewrite to do so. 
For your information, rewrite rules are interpreted before authentication. That's why why need a "look ahead" variable which will take its final value during the fixup phase.
~~~~
RewriteEngine On
RewriteCond %{LA-U:REMOTE_USER} (.+)
RewriteRule . - [E=RU:%1]
RequestHeader set X-Remote-User "%{RU}e" env=RU
~~~~
## Configuration examples

This configuration is given for tests purpose. Remember to always use TLS in production.

With HMAC algorithm:
~~~~
<VirtualHost *:80>
	ServerName example.com
	DocumentRoot /var/www/html/

	# default values
	AuthJWTFormUsername user
	AuthJWTFormPassword password
	AuthJWTAttributeUsername user
	
	AuthJWTSignatureAlgorithm HS256
	AuthJWTSignatureSharedSecret Q0hBTkdFTUU=
	AuthJWTExpDelay 1800
	AuthJWTNbfDelay 0
	AuthJWTIss example.com
	AuthJWTAud demo
	AuthJWTLeeway 10

	<Directory /var/www/html/demo/secured/>
		AllowOverride None
		AuthType jwt
		AuthName "private area"
		Require valid-user
	</Directory>
	
	
	<Location /demo/login>
		SetHandler jwt-login-handler
		AuthJWTProvider file
		AuthUserFile /var/www/jwt.htpasswd
	</Location>

	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
~~~~

With EC algorithm:
~~~~
<VirtualHost *:80>
	ServerName example.com
	DocumentRoot /var/www/html/

	# default values
	AuthJWTFormUsername user
	AuthJWTFormPassword password
	AuthJWTAttributeUsername user
	
	AuthJWTSignatureAlgorithm ES256
	AuthJWTSignaturePublicKeyFile /etc/pki/auth_pub.pem
	AuthJWTSignaturePrivateKeyFile /etc/pki/auth_priv.pem
	AuthJWTExpDelay 1800
	AuthJWTNbfDelay 0
	AuthJWTIss example.com
	AuthJWTAud demo
	AuthJWTLeeway 10

	<Directory /var/www/html/demo/secured/>
		AllowOverride None
		AuthType jwt
		AuthName "private area"
		Require valid-user
	</Directory>
	
	
	<Location /demo/login>
		SetHandler jwt-login-handler
		AuthJWTProvider file
		AuthUserFile /var/www/jwt.htpasswd
	</Location>

	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
~~~~

With Cookie:
~~~~
<VirtualHost *:80>
	ServerName example.com
	DocumentRoot /var/www/html/

	# default values
	AuthJWTFormUsername user
	AuthJWTFormPassword password
	AuthJWTAttributeUsername user

	AuthJWTSignatureAlgorithm HS256
	AuthJWTSignatureSharedSecret Q0hBTkdFTUU=
	AuthJWTExpDelay 1800
	AuthJWTNbfDelay 0
	AuthJWTIss example.com
	AuthJWTAud demo
	AuthJWTLeeway 10

    AuthJWTDeliveryType Cookie

	<Directory /var/www/html/demo/secured/>
		AllowOverride None
		AuthType jwt-cookie
		AuthName "private area"
		Require valid-user
	</Directory>


	<Location /demo/login>
		SetHandler jwt-login-handler
		AuthJWTProvider file
		AuthUserFile /var/www/jwt.htpasswd
	</Location>

	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
~~~~

## Documentation

#### Directives

##### AuthType
* **Description**: Authentication type to allow. `jwt` and `jwt-bearer` will allow only the Authorization header. `jwt-cookie` allows only Cookie usage. `jwt-both` accepts Authorization header and cookie. Cookie value will be ignored if Authorization header is set.
* **Context**: directory
* **Possibles values**: jwt, jwt-bearer, jwt-cookie, jwt-both

##### AuthJWTProvider 

* **Description**: Authentication providers used
* **Context**: directory

##### AuthJWTSignatureAlgorithm 

* **Description**: The algorithm to use to sign tokens
* **Context**: server config, directory
* **Default**: HS256
* **Possibles values**: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512
* **Mandatory**: yes

##### AuthJWTSignatureSharedSecret 

* **Description**: The secret to use to sign tokens with HMACs. It must be base64 encoded.
* **Context**: server config, directory
* **Mandatory**: no

##### AuthJWTSignaturePublicKeyFile

* **Description**: The file path of public key used with either RSA or EC algorithms.
* **Context**: server config, directory
* **Mandatory**: no

##### AuthJWTSignaturePrivateKeyFile 

* **Description**: The file path of private key used with either RSA or EC algorithms.
* **Context**: server config, directory
* **Mandatory**: no

##### AuthJWTIss
* **Description**: The issuer of delivered tokens
* **Context**: server config, directory
* **Mandatory**: no

##### AuthJWTAud
* **Description**: The audience of delivered tokens
* **Context**: server config, directory
* **Mandatory**: no

##### AuthJWTExpDelay 
* **Description**: The time delay in seconds after which delivered tokens are considered invalid
* **Context**: server config, directory
* **Default**: 1800
* **Mandatory**: no

##### AuthJWTNbfDelay 
* **Description**: The time delay in seconds before which delivered tokens must not be processed
* **Context**: server config, directory
* **Default**: 0
* **Mandatory**: no

##### AuthJWTLeeway 
* **Description**: The leeway to account for clock skew in token validation process
* **Context**: server config, directory
* **Default**: 0
* **Mandatory**: no

##### AuthJWTFormUsername
* **Description**: The name of the field containing the username in authentication process
* **Context**: server config, directory
* **Default**: user
* **Mandatory**: no

##### AuthJWTFormPassword
* **Description**: The name of the field containing the password in authentication process
* **Context**: server config, directory
* **Default**: password
* **Mandatory**: no

##### AuthJWTAttributeUsername
* **Description**: The name of the attribute containing the username in the token (used for authorization as well as token generation)
* **Context**: server config, directory
* **Default**: user
* **Mandatory**: no

##### AuthJWTDeliveryType
* **Description**: Type of token delivery JSON or Cookie (case-sensitive)
* **Context**: server config, directory
* **Default**: JSON
* **Possibles values**: JSON, Cookie
* **Mandatory**: no

##### AuthJWTTokenName
* **Description**: Token name to use when using JSON delivery
* **Context**: server config, directory
* **Default**: token
* **Mandatory**: no

##### AuthJWTCookieName
* **Description**: Cookie name to use when using cookie delivery
* **Context**: server config, directory
* **Default**: AuthToken
* **Mandatory**: no

##### AuthJWTCookieAttr
* **Description**: Semi-colon separated attributes for cookie when using cookie delivery
* **Context**: server config, directory
* **Default**: Secure;HttpOnly;SameSite
* **Mandatory**: no

##### AuthJWTRemoveCookie
* **Description**: Remove cookie from the headers, and thus keep it private from the backend
* **Context**: server config, directory
* **Default**: 1
* **Mandatory**: no
