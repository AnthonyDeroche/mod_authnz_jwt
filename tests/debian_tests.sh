#!/bin/bash
set -ev
sudo cp apache_jwt.conf /etc/apache2/sites-available/
sudo cp jwt.htpasswd /var/www/jwt.htpasswd
sudo mkdir -p /var/www/testjwt/
sudo touch /var/www/testjwt/index.html

openssl ecparam -name secp256k1 -genkey -noout -out /tmp/ec-priv.pem
openssl ec -in /tmp/ec-priv.pem -pubout -out /tmp/ec-pub.pem

openssl genpkey -algorithm RSA -out /tmp/rsa-priv.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout -in /tmp/rsa-priv.pem -out /tmp/rsa-pub.pem

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

python3 -m unittest discover . -v -f --locals
