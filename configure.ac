AC_PREREQ([2.63])

AC_INIT([xdg-dbus-proxy],[0.1.2])
AC_CONFIG_AUX_DIR([build-aux])

m4_pattern_forbid([^AX_CODE_COVERAGE$],
  [Unexpanded AX_CODE_COVERAGE macro found. Please install GNU autoconf-archive])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

AC_PROG_CC
AM_PROG_CC_C_O

AC_CONFIG_SRCDIR([dbus-proxy.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 no-define no-dist-gzip dist-xz tar-ustar foreign subdir-objects])

# Enable silent rules is available
AM_SILENT_RULES([yes])
AM_MAINTAINER_MODE([enable])

if test "x$GCC" = "xyes"; then
  case " $CFLAGS " in
  *[[\ \	]]-Wall[[\ \	]]*) ;;
  *) CFLAGS="$CFLAGS -Wall" ;;
  esac
fi

PKG_CHECK_MODULES(GLIB, [glib-2.0 >= 2.40 gio-2.0 gio-unix-2.0])
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

AC_PROG_AWK
AC_REQUIRE_AUX_FILE([tap-driver.sh])
GLIB_TESTS

# Test for code-coverage tools if --enable-code-coverage
AX_CODE_COVERAGE

AC_ARG_ENABLE(man,
              [AS_HELP_STRING([--enable-man],
                              [generate man pages [default=auto]])],,
              enable_man=maybe)

AS_IF([test "$enable_man" != no], [
  AC_PATH_PROG([XSLTPROC], [xsltproc], [])
  AS_IF([test -z "$XSLTPROC"], [
    AS_IF([test "$enable_man" = yes], [
      AC_MSG_ERROR([xsltproc is required for --enable-man])
    ])
    enable_man=no
  ], [
    enable_man=yes
  ])
])
AM_CONDITIONAL(ENABLE_MAN, test "$enable_man" != no)

AC_CONFIG_FILES([
Makefile
])
AC_OUTPUT
