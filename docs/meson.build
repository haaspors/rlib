run_target('docs',
  command : ['hotdoc', 'run',
    '--conf-file', meson.current_source_dir() + '/hotdoc.json',
    '--c-include-directories', meson.current_build_dir() + '/..', meson.current_source_dir() + '/../include',
    '-o', meson.current_build_dir()],
  depends : [librlib])
