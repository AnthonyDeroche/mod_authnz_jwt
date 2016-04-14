APXS=apxs

.DEFAULT_GOAL:= build
.PHONY: install build clean

install: mod_authnz_jwt.la
	$(APXS) -i -a mod_authnz_jwt.la

build: mod_authnz_jwt.la

mod_authnz_jwt.la: mod_authnz_jwt.c
	$(APXS) -c mod_authnz_jwt.c -lz -ljwt

clean:
	rm -rf mod_authnz_jwt.so mod_authnz_jwt.o \
	    mod_authnz_jwt.la mod_authnz_jwt.slo \
	    mod_authnz_jwt.lo .libs
