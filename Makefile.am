bin_PROGRAMS=xdg-dbus-proxy

xdg_dbus_proxy_SOURCES = \
	flatpak-proxy.c	\
	flatpak-proxy.h	\
	dbus-proxy.c	\
	backport-autoptr.h \
	$(NULL)

xdg_dbus_proxy_LDADD = $(AM_LDADD) $(GLIB_LIBS)
xdg_dbus_proxy_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS)
