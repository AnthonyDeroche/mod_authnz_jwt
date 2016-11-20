#!/bin/bash
set -ev
sudo cp apache_hmac.conf /etc/apache2/sites-available/
sudo mkdir -p /var/www/testjwt/jwt_secured/
sudo touch /var/www/testjwt/jwt_secured/index.html
sudo cp jwt.htpasswd /var/www/jwt.htpasswd

if ! sudo a2query -s apache_hmac > /dev/null; then
	sudo a2ensite apache_hmac
	sudo service apache2 restart
fi

if ! grep -q "hmac.testjwt.local" /etc/hosts; then
	echo "127.0.0.1 hmac.testjwt.local" | sudo tee --append /etc/hosts > /dev/null
fi

python3 -m unittest discover . -v -f --locals
