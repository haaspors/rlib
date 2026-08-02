
examples = [
  'ralloc',
  'rargparse',
  'rassert',
  'ratomic',
  'rfile',
  'rlog',
  'ronce',
  'rprint',
  'rtest',
  'rmachodump',
  'rmodulesection',
  'rpedump',
  'rthratomic',
  'rthreadaffinity',
  'rthreadsleep',
  'rturnserver',
  'rice',
]

foreach e : examples
  executable(e, e + '.c',
    include_directories : inc,
    dependencies : [ libm, libdl, libthread, librt ],
    link_with : librlib,
    install : false)
endforeach

