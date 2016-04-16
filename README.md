#mod_authnz_jwt

Authentication module for Apache httpd with JSON web tokens (JWT).
More on JWT : https://jwt.io/

## Build Requirements

- libjwt (https://github.com/benmcollins/libjwt)
- Apache development package (apache2-dev on Debian/Ubuntu and httpd-devel on CentOS/Fedora)

## Documentation

###Directives

####AuthJWTProvider 

* Description: Authentication providers used
* Context: directory

####AuthJWTSignatureAlgorithm 

* Description: The algorithm to use to sign tokens
* Context: erver config, directory
* Default: HS256
* Possibles values: HS256, HS384, HS512
* Mandatory: yes

####AuthJWTSignatureSecret 

* Description: The secret to use to sign tokens with HMACs. Secret length must be respectively 32, 48, 64 for HS256, HS384, HS512.
* Context: erver config, directory
* Mandatory: yes

####AuthJWTIss
* Description: The issuer of delievered tokens
* Context: erver config, directory
* Mandatory: no

####AuthJWTAud
* Description: The audience of delivered tokens
* Context: erver config, directory
* Mandatory: no

####AuthJWTSub
* Description: The subject of delivered tokens
* Context: erver config, directory
* Mandatory: no

####AuthJWTExpDelay 
* Description: The time delay in seconds after which delivered tokens are considered invalid
* Context: erver config, directory
* Default: 1800
* Mandatory: no

####AuthJWTNbfDelay 
* Description: The time delay in seconds before which delivered tokens must not be processed
* Context: erver config, directory
* Default: 0
* Mandatory: no

####AuthJWTLeeway 
* Description: The leeway to account for clock skew in token validation process
* Context: erver config, directory
* Default: 0
* Mandatory: no

## TODO

- Possibility to disable checks on exp, nbf, iss, aud, sub
- Authorization based on token public fields

