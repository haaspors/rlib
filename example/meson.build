
examples = [
  'ralloc',
  'rassert',
  'ratomic',
  'rfile',
  'rlog',
  'ronce',
  'ropt',
  'rprint',
  'rtest',
  'rmodulesection',
  'rthratomic',
  'rthreadaffinity',
  'rthreadsleep',
]

foreach e : examples
  executable(e, e + '.c',
    include_directories : inc,
    dependencies : [ libm, libdl, libthread, librt ],
    link_with : rlibsh,
    link_args : '-rdynamic',
    install : false)
endforeach

