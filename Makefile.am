ACLOCAL_AMFLAGS = -I acinclude.d

noinst_LTLIBRARIES = libmodauthnzjwt.la
noinst_DATA = mod_authnz_jwt.la

AM_CPPFLAGS = ${APACHE_CFLAGS} ${JWT_CFLAGS} ${JANSSON_CFLAGS} ${Z_CFLAGS}
AM_LDFLAGS = ${JWT_LIBS} ${JANSSON_LDFLAGS} ${Z_LIBS} ${APR_LDFLAGS}

libmodauthnzjwt_la_SOURCES = mod_authnz_jwt.c

AM_CXXFLAGS = -Wall

if NITPICK
AM_CXXFLAGS += -Wextra -Wundef -Wshadow -Wunsafe-loop-optimizations -Wconversion -Wmissing-format-attribute
AM_CXXFLAGS += -Wredundant-decls -ansi -Wmissing-noreturn
endif

if DEBUG
AM_CXXFLAGS += -DDEBUG
endif

install-exec-local:
	${APXS} -i -a -n 'auth_jwt' mod_authnz_jwt.la

mod_authnz_jwt.la: libmodauthnzjwt.la
	${APXS} -c -o $@ $< ${APACHE_CFLAGS} ${JWT_CFLAGS} ${JWT_LIBS} \
		${JANSSON_CFLAGS} ${JANSSON_LDFLAGS} ${Z_CFLAGS} ${Z_LIBS}
