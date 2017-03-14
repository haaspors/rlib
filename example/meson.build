
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
  'rthratomic',
  'rthreadaffinity',
  'rthreadsleep',
]

foreach e : examples
  executable(e, e + '.c',
    include_directories : inc,
    link_with : rlibsh,
    link_args : '-rdynamic',
    install : false)
endforeach

