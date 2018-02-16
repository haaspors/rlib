
rlibbench = executable('rlibbench', ['revudp.c', 'main.c'],
  include_directories : inc,
  link_with : rlibsh,
  install : false)

benchmark('rlib benchmark', rlibbench)
