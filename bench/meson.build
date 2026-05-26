
rlibbench = executable('rlibbench', ['recdh.c', 'revudp.c', 'rdsa.c', 'rrsa.c', 'main.c'],
  include_directories : inc,
  link_with : librlib,
  install : false)

benchmark('rlib benchmark', rlibbench)
