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

COPY --from=stage1 /usr/local/lib/libjwt.so.0.7.0 /usr/local/lib/libjwt.so
COPY --from=stage1 /usr/lib/apache2/modules/mod_authnz_jwt.so /usr/lib/apache2/modules/mod_authnz_jwt.so

EXPOSE 80
CMD ["apachectl", "-D", "FOREGROUND"]