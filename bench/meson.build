
rlibbench = executable('rlibbench', ['raes.c', 'recdh.c', 'recdsa.c', 'revudp.c', 'rdh.c', 'rdsa.c', 'rrsa.c', 'main.c'],
  include_directories : inc,
  link_with : librlib,
  install : false)

benchmark('rlib benchmark', rlibbench)
