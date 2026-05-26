
rlibbench = executable('rlibbench', ['revudp.c', 'rdsa.c', 'rrsa.c', 'main.c'],
  include_directories : inc,
  link_with : librlib,
  install : false)

benchmark('rlib benchmark', rlibbench)
