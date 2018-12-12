# vim:set ft=automake:

AM_TESTS_ENVIRONMENT += \
	DBUS_PROXY=${abs_top_builddir}/xdg-dbus-proxy \
	$(NULL)

test_programs = \
	test-proxy \
	$(NULL)

test_proxy_CPPFLAGS = -DBINDIR=\"$(bindir)\"
test_proxy_SOURCES = tests/test-proxy.c
test_proxy_LDADD = $(COMMON_LIBS)
