#mod_authnz_jwt

Authentication module for Apache httpd with JSON web tokens (JWT).

More on JWT : https://jwt.io/

On the first hand, this module is able to deliver JSON web tokens containing all public fields (iss, aud, sub, iat, nbf, exp), and the private field "user". Authentication process is carried out by an authentication provider and spicified by the AuthJWTProvider directive.

On the other hand, this module is able to check validity of token based on its signature, and on its public fields. If the token is valid, then the user is authenticated and can be used by an authorization provider with the directive "Require valid-user" to authorize or not the request.

Although this module is able to deliver valid tokens, it may be used to check tokens delivered by a custom application in any language, as long as a secret is shared between the two parts. This feature is possible because token-based authentication is stateless.

Note that this module does not support asymetric algorithms such as RSA or DSA to check signature for the moment.

## Build Requirements

- libjwt v1.3.1 (https://github.com/benmcollins/libjwt)
- Apache development package (apache2-dev on Debian/Ubuntu and httpd-devel on CentOS/Fedora)

## Documentation

####Directives

#####AuthJWTProvider 

* **Description**: Authentication providers used
* **Context**: directory

#####AuthJWTSignatureAlgorithm 

* **Description**: The algorithm to use to sign tokens
* **Context**: server config, directory
* **Default**: HS256
* **Possibles values**: HS256, HS384, HS512
* **Mandatory**: yes

#####AuthJWTSignatureSecret 

* **Description**: The secret to use to sign tokens with HMACs. Secret length must be respectively 32, 48, 64 for HS256, HS384, HS512.
* **Context**: server config, directory
* **Mandatory**: yes

#####AuthJWTIss
* **Description**: The issuer of delievered tokens
* **Context**: server config, directory
* **Mandatory**: no

#####AuthJWTAud
* **Description**: The audience of delivered tokens
* **Context**: server config, directory
* **Mandatory**: no

#####AuthJWTSub
* **Description**: The subject of delivered tokens
* **Context**: server config, directory
* **Mandatory**: no

#####AuthJWTExpDelay 
* **Description**: The time delay in seconds after which delivered tokens are considered invalid
* **Context**: server config, directory
* **Default**: 1800
* **Mandatory**: no

#####AuthJWTNbfDelay 
* **Description**: The time delay in seconds before which delivered tokens must not be processed
* **Context**: server config, directory
* **Default**: 0
* **Mandatory**: no

#####AuthJWTLeeway 
* **Description**: The leeway to account for clock skew in token validation process
* **Context**: server config, directory
* **Default**: 0
* **Mandatory**: no

## Configuration example

~~~~
<VirtualHost *:80>
	ServerName deroche.me
	DocumentRoot /var/www/html/
	
	AuthJWTSignatureAlgorithm HS256
	AuthJWTSignatureSecret CHANGEME--32--characters--secret
	AuthJWTExpDelay 1800
	AuthJWTNbfDelay 0
	AuthJWTIss deroche.me
	AuthJWTSub jwt-demo
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

## Demo

https://deroche.me/demo/jwt.php

## TODO
- Adapt code to last version of libjwt
- Possibility to disable checks on exp, nbf, iss, aud, sub
- Authorization based on token public fields
- Merge confs
