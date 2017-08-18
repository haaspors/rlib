
rlibbench = executable('rlibbench', ['revudp.c', 'main.c'],
  include_directories : inc,
  link_with : rlibsh,
  link_args : '-rdynamic',
  install : false)

benchmark('rlib benchmark', rlibbench)
