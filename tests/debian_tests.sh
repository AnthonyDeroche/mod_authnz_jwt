#!/bin/bash
set -ev
sudo cp apache_jwt.conf /etc/apache2/sites-available/
sudo cp jwt.htpasswd /var/www/jwt.htpasswd
sudo mkdir -p /var/www/testjwt/
sudo touch /var/www/testjwt/index.html

sudo mkdir -p /opt/mod_jwt_tests

sudo openssl ecparam -name secp256k1 -genkey -noout -out /opt/mod_jwt_tests/ec-priv.pem
sudo openssl ec -in /opt/mod_jwt_tests/ec-priv.pem -pubout -out /opt/mod_jwt_tests/ec-pub.pem

sudo openssl genpkey -algorithm RSA -out /opt/mod_jwt_tests/rsa-priv.pem -pkeyopt rsa_keygen_bits:4096
sudo openssl rsa -pubout -in /opt/mod_jwt_tests/rsa-priv.pem -out /opt/mod_jwt_tests/rsa-pub.pem

sudo chmod 644 /opt/mod_jwt_tests/*.pem


if ! sudo a2query -m rewrite > /dev/null; then
	sudo a2enmod rewrite
fi
if ! sudo a2query -s apache_jwt > /dev/null; then
	sudo a2ensite apache_jwt
fi
sudo service apache2 restart

if ! grep -q "testjwt.local" /etc/hosts; then
	echo "127.0.0.1 testjwt.local" | sudo tee --append /etc/hosts > /dev/null
fi

python3 -m unittest discover . -v -f
