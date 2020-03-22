xdg-dbus-proxy
==============

xdg-dbus-proxy is a filtering proxy for D-Bus connections. It was originally
part of the flatpak project, but it has been broken out as a standalone module
to facilitate using it in other contexts.

Building
--------

You need to have autotools installed. On Debian, don't forget to install 
`autoconf-archive` too.

- Run `./autogen.sh`. It will generate configure script and Makefile
- Run `./configure` (see `./configure --help` for additional options)
- Run `make`
- Run `make install`

To build debug version you can add flags to make, for example: 

	make -e CFLAGS="-g -O0 -fsanitize=address" LDFLAGS="-fsanitize=address"

Usage example
-------------

Start proxy with:

	xdg-dbus-proxy "$DBUS_SESSION_BUS_ADDRESS" /tmp/proxy.socket --log 

Test it using: 

	DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/proxy.socket dbus-send --session --dest=org.freedesktop.DBus --print-reply /org/freedesktop/DBus org.freedesktop.DBus.ListNames

This will display a list of D-Bus names visible through the proxy. You can 
also use programs like D-Feet to examine the bus.
