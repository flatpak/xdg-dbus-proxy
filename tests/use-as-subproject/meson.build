project(
  'use-xdg-dbus-proxy-as-subproject',
  'c',
  version : '0',
  meson_version : '>=0.49.0',
)

configure_file(
  output : 'config.h',
  input : 'dummy-config.h.in',
  configuration : configuration_data(),
)

subproject(
  'dbus-proxy',
  default_options : [
    'program_prefix=notflatpak-',
  ],
)
