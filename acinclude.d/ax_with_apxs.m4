# some code taken from mod_python's (http://www.modpython.org/) configure.in

AC_DEFUN([AX_WITH_APXS],
[

# check for --with-apxs
AC_MSG_CHECKING(for --with-apxs)
AC_ARG_WITH(apxs, AC_HELP_STRING([--with-apxs=PATH], [Path to apxs]),
[
  if test -x "$withval"
  then
    AC_MSG_RESULT([$withval executable, good])
    APXS=$withval
  else
    echo
    AC_MSG_ERROR([$withval not found or not executable])
  fi
],
AC_MSG_RESULT(no))

# find apxs
if test -z "$APXS"; then
  AC_PATH_PROGS([APXS],[apxs2 apxs],[false],[${PATH}:/usr/local/bin:/usr/local/sbin:/usr/sbin:/sbin])
  test "${APXS}" = "false" && AC_MSG_ERROR([failed to find apxs. Try using --with-apxs])
fi

  # check Apache version
  AC_MSG_CHECKING(Apache version)
  HTTPD="`${APXS} -q SBINDIR`/`${APXS} -q TARGET`"
  if test ! -x "$HTTPD"; then
    AC_MSG_ERROR($APXS says that your apache binary lives at $HTTPD but that file isn't executable.  Specify the correct apxs location with --with-apxs)
  fi
  ver=`$HTTPD -v | /usr/bin/awk '/version/ {print $3}' | /usr/bin/awk -F/ '{print $2}'`
  AC_MSG_RESULT($ver)

  # make sure version begins with 2
  if test -z "`$HTTPD -v | egrep 'Server version: Apache/2'`"; then
    AC_MSG_ERROR([mod_auth_openid only works with Apache 2. The one you have seems to be $ver.])
  fi

AC_SUBST(APXS)
])
