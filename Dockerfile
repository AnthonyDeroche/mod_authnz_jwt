FROM debian:bullseye-slim as stage1
LABEL MAINTAINER="Anthony Deroche <anthony@deroche.me>"
ARG LIBJWT_VERSION=1.12.0

RUN apt-get update && apt-get install -y git libtool pkg-config autoconf libssl-dev check libjansson-dev make

WORKDIR /opt

RUN git clone https://github.com/benmcollins/libjwt && \
    cd libjwt && \
    git checkout tags/v${LIBJWT_VERSION} && \
    autoreconf -i && \
    ./configure && \
    make && \
    make install

RUN apt-get install -y apache2 apache2-dev zlib1g-dev

ADD . /opt/mod_authnz_jwt

WORKDIR /opt/mod_authnz_jwt

RUN autoreconf -ivf  && \
    ./configure && \
    make && \
    make install

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y apache2

COPY --from=stage1 /usr/local/lib/libjwt.so.0.7.0 /usr/lib/x86_64-linux-gnu/libjwt.so.0
COPY --from=stage1 /usr/lib/apache2/modules/mod_authnz_jwt.so /usr/lib/apache2/modules/mod_authnz_jwt.so
COPY tests/authnz_jwt.load /etc/apache2/mods-available/authnz_jwt.load

RUN mkdir -p /opt/mod_jwt_tests
RUN openssl ecparam -name secp256k1 -genkey -noout -out /opt/mod_jwt_tests/ec-priv.pem && \
    openssl ec -in /opt/mod_jwt_tests/ec-priv.pem -pubout -out /opt/mod_jwt_tests/ec-pub.pem
RUN openssl genpkey -algorithm RSA -out /opt/mod_jwt_tests/rsa-priv.pem -pkeyopt rsa_keygen_bits:4096 && \
    openssl rsa -pubout -in /opt/mod_jwt_tests/rsa-priv.pem -out /opt/mod_jwt_tests/rsa-pub.pem

RUN mkdir -p /var/www/testjwt && touch /var/www/testjwt/index.html
COPY tests/apache_jwt.conf /etc/apache2/sites-available/apache_jwt.conf
COPY tests/jwt.htpasswd /var/www/jwt.htpasswd

RUN a2query -m rewrite || a2enmod rewrite
RUN a2query -m authnz_jwt || a2enmod authnz_jwt
RUN a2query -s apache_jwt || a2ensite apache_jwt

EXPOSE 80
CMD ["apachectl", "-D", "FOREGROUND"]