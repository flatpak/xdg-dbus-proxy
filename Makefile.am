include $(top_srcdir)/build-aux/glib-tap.mk

AM_CFLAGS = $(GLIB_CFLAGS)

bin_PROGRAMS=xdg-dbus-proxy

xdg_dbus_proxy_SOURCES = \
	flatpak-proxy.c	\
	flatpak-proxy.h	\
	dbus-proxy.c	\
	backport-autoptr.h \
	$(NULL)

xdg_dbus_proxy_LDADD = $(AM_LDADD) $(GLIB_LIBS)

include Makefile-docs.am
include tests/Makefile.am.inc

EXTRA_DIST += build-aux/glib-tap.mk
EXTRA_DIST += build-aux/tap-test
