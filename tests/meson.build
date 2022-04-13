test_programs = [
  [
    'test-proxy',
    executable(
      'test-proxy',
      'test-proxy.c',
      dependencies : common_deps,
      include_directories : common_include_directories,
    ),
  ],
]

test_env = environment()
test_env.set('DBUS_PROXY', dbus_proxy.full_path())
test_env.set('G_TEST_BUILDDIR', meson.current_build_dir())
test_env.set('G_TEST_SRCDIR', meson.current_source_dir())

foreach pair : test_programs
  name = pair[0]
  test_program = pair[1]
  if meson.version().version_compare('>=0.50.0')
    test(
      name,
      test_program,
      env : test_env,
      protocol : 'tap',
    )
  else
    test(
      name,
      test_program,
      env : test_env,
    )
  endif
endforeach
