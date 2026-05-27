
rlibbench = executable('rlibbench', ['raes.c', 'rcrc.c', 'rdh.c', 'rdsa.c', 'recdh.c', 'recdsa.c', 'recurve_edwards.c', 'recurve_montgomery.c', 'red25519.c', 'red448.c', 'revudp.c', 'rhmac.c', 'rmsgdigest.c', 'rrsa.c', 'rxdh.c', 'main.c'],
  include_directories : inc,
  link_with : librlib,
  install : false)

benchmark('rlib benchmark', rlibbench)
