#mod_authnz_jwt

Authentication module for Apache httpd with JSON web tokens (JWT).

More on JWT : https://jwt.io/

Supported algorithms : HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512
Supported checks : iss, aud, exp, nbf

This module is able to deliver JSON web tokens containing all public fields (iss, aud, sub, iat, nbf, exp), and the private field "user". Authentication process is carried out by an authentication provider and specified by the AuthJWTProvider directive.

On the other hand, this module is able to check validity of token based on its signature, and on its public fields. If the token is valid, then the user is authenticated and can be used by an authorization provider with the directive "Require valid-user" to authorize or not the request.

Although this module is able to deliver valid tokens, it may be used to check tokens delivered by a custom application in any language, as long as a secret is shared between the two parts. This feature is possible because token-based authentication is stateless.

## Build Requirements

- libjwt (https://github.com/benmcollins/libjwt)
- Apache development package (apache2-dev on Debian/Ubuntu and httpd-devel on CentOS/Fedora)

## Quick start

### Installation from sources
~~~~
sudo apt-get install libtool pkg-config autoconf libssl-dev check libjansson-dev
git clone https://github.com/benmcollins/libjwt
cd libjwt
autoreconf -i
./configure
make
sudo make install
cd ..
sudo apt-get install apache2 apache2-dev
git clone https://github.com/AnthonyDeroche/mod_authnz_jwt
cd mod_authnz_jwt
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
openssl genpkey -algorit RSA -out rsa-priv.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout -in rsa-priv.pem -out rsa-pub.pem
~~~~

## Configuration examples

This configuration is given for tests purpose. Remember to always use TLS in production.

With HMAC algorithm:
~~~~
<VirtualHost *:80>
	ServerName deroche.me
	DocumentRoot /var/www/html/

	# default values
	AuthJWTFormUsername user
	AuthJWTFormPassword password
	AuthJWTAttributeUsername user
	
	AuthJWTSignatureAlgorithm HS256
	AuthJWTSignatureSharedSecret CHANGEME
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

With EC algorithm:
~~~~
<VirtualHost *:80>
	ServerName deroche.me
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


## Documentation

####Directives

#####AuthJWTProvider 

* **Description**: Authentication providers used
* **Context**: directory

#####AuthJWTSignatureAlgorithm 

* **Description**: The algorithm to use to sign tokens
* **Context**: server config, directory
* **Default**: HS256
* **Possibles values**: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512
* **Mandatory**: yes

#####AuthJWTSignatureSharedSecret 

* **Description**: The secret to use to sign tokens with HMACs.
* **Context**: server config, directory
* **Mandatory**: no

#####AuthJWTSignaturePublicKeyFile

* **Description**: The file path of public key used with either RSA or EC algorithms.
* **Context**: server config, directory
* **Mandatory**: no

#####AuthJWTSignaturePrivateKeyFile 

* **Description**: The file path of private key used with either RSA or EC algorithms.
* **Context**: server config, directory
* **Mandatory**: no

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

#####AuthJWTFormUsername
* **Description**:The name of the field containing the username in authentication process
* **Context**: server config, directory
* **Default**: user
* **Mandatory**: no

#####AuthJWTFormPassword
* **Description**:The name of the field containing the password in authentication process
* **Context**: server config, directory
* **Default**: password
* **Mandatory**: no

#####AuthJWTAttributeUsername
* **Description**:The name of the attribute containing the username in the token (used for authorization as well as token generation)
* **Context**: server config, directory
* **Default**: user
* **Mandatory**: no

## Demo
<a href="https://anthony.deroche.me/demo/jwt.php" target="_blank">https://anthony.deroche.me/demo/jwt.php</a>


