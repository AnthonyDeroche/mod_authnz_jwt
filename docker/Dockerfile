FROM debian:buster-slim as build

WORKDIR /build

RUN apt-get update && \
  apt-get install -y ca-certificates make automake git g++ libtool pkg-config autoconf libssl-dev check libjansson-dev libz-dev procps apache2 apache2-dev
  
ARG LIBJWT_VERSION=1.12.1
ARG MOD_AUTHNZ_JWT_VERSION=1.2.0

RUN git clone https://github.com/benmcollins/libjwt.git && \
    cd libjwt && \
    git checkout tags/v$LIBJWT_VERSION && \
    autoreconf -i && \
    ./configure && \
    make && \
    make install

RUN git clone https://github.com/AnthonyDeroche/mod_authnz_jwt.git && \
    cd mod_authnz_jwt && \
    git checkout tags/v$MOD_AUTHNZ_JWT_VERSION && \
    autoreconf -ivf && \
    PKG_CONFIG_PATH=/usr/local ./configure && \
    make && \
    make install
    
FROM httpd:2.4

COPY --from=build /usr/local/lib/libjwt.so /usr/lib/x86_64-linux-gnu/libjwt.so.1
COPY --from=build /usr/lib/apache2/modules/mod_authnz_jwt.so /usr/local/apache2/modules/mod_authnz_jwt.so

RUN echo "LoadModule auth_jwt_module modules/mod_authnz_jwt.so" >> /usr/local/apache2/conf/httpd.conf

