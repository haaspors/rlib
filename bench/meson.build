
rlibbench = executable('rlibbench', ['revudp.c', 'rrsa.c', 'main.c'],
  include_directories : inc,
  link_with : librlib,
  install : false)

benchmark('rlib benchmark', rlibbench)
