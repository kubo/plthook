project(
  'plthook',
  'c',
  version: '0.1.0',
  license: 'BSD-2-Clause',
  meson_version: '>=0.56.0',
)

inc = include_directories('.')

if host_machine.system() in ['windows', 'cygwin']
  src = files('plthook_win32.c')
elif host_machine.system() == 'darwin'
  src = files('plthook_osx.c')
elif host_machine.system() in [
  'linux',
  'dragonfly',
  'freebsd',
  'netbsd',
  'openbsd',
  'sunos',
  'android',
  'haiku',
]
  src = files('plthook_elf.c')
endif

hdrs = files('plthook.h')

plthook_lib = library(
  'plthook',
  src + hdrs,
  include_directories: inc,
)

install_headers(hdrs)

plthook_dep = declare_dependency(
  link_with: plthook_lib,
  include_directories: inc,
)

meson.override_dependency('plthook', plthook_dep)
