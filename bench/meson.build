
rlibbench = executable('rlibbench', ['raes.c', 'rdh.c', 'rdsa.c', 'recdh.c', 'recdsa.c', 'revudp.c', 'rhmac.c', 'rmsgdigest.c', 'rrsa.c', 'main.c'],
  include_directories : inc,
  link_with : librlib,
  install : false)

benchmark('rlib benchmark', rlibbench)
