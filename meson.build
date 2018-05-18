project('rlib', 'c',
  version : '1.0.0',
  meson_version : '>=0.46',
  default_options : [
    'buildtype=debugoptimized',
    'default_library=both',
  ])

rlib_name = meson.project_name()
rlib_version = meson.project_version()
rlib_api_version = '1.0'
rlib_build_target = meson.get_cross_property('build_target', 'library')

cc = meson.get_compiler('c')
inc = include_directories([ '.', 'include' ])
conf = configuration_data()
rconf = configuration_data()

install_subdir('include', install_dir : '')

if host_machine.system() != 'windows'
  add_global_arguments('-D_GNU_SOURCE=1', language : 'c')
endif


# ARCH
if host_machine.cpu() == 'x86_64' or host_machine.cpu() == 'amd64' or host_machine.cpu() == 'x64'
  rconf.set('R_ARCH_X86_64', 1)
elif host_machine.cpu() == 'x86'
  rconf.set('R_ARCH_X86', 1)
elif host_machine.cpu() == 'ia'
  rconf.set('R_ARCH_IA64', 1)
elif host_machine.cpu() == 'arm'
  rconf.set('R_ARCH_ARM', 1)
elif host_machine.cpu() == 'thumb'
  rconf.set('R_ARCH_THUMB', 1)
elif host_machine.cpu() == 'aarch64'
  rconf.set('R_ARCH_AARCH64', 1)
elif host_machine.cpu() == 'sparc'
  rconf.set('R_ARCH_SPARC', 1)
elif host_machine.cpu() == 'xtensa'
  rconf.set('R_ARCH_XTENSA', 1)
else
  error('architecture ' + host_machine.cpu() + 'not supported')
endif


# OS
if host_machine.system() == 'bare'
  rconf.set('R_OS_BARE_METAL', 1)
elif host_machine.system() == 'windows'
  rconf.set('R_OS_WIN32', 1)
elif host_machine.system() == 'linux'
  rconf.set('R_OS_UNIX', 1)
  rconf.set('R_OS_LINUX', 1)
elif host_machine.system() == 'darwin'
  rconf.set('R_OS_UNIX', 1)
  rconf.set('R_OS_BSD', 1)
  rconf.set('R_OS_DARWIN', 1)
elif host_machine.system() == 'rtems'
  rconf.set('R_OS_UNIX', 1)
  rconf.set('R_OS_RTEMS', 1)
endif


# SIZEOF
sizeof_short = cc.sizeof('short')
sizeof_int = cc.sizeof('int')
sizeof_long = cc.sizeof('long')
sizeof_longlong = cc.sizeof('long long')
sizeof_size_t = cc.sizeof('size_t')
sizeof_void_p = cc.sizeof('void*')

if sizeof_short == 2
  rconf.set('RINT16_TYPE', 'short')
  rconf.set('RINT16_MODIFIER', '"h"')
  rconf.set('RINT16_FMT', '"hi"')
  rconf.set('RUINT16_FMT', '"hu"')
elif sizeof_int == 2
  rconf.set('RINT16_TYPE', 'int')
  rconf.set('RINT16_MODIFIER', '""')
  rconf.set('RINT16_FMT', '"i"')
  rconf.set('RUINT16_FMT', '"u"')
else
  error('No 16bit type found')
endif

if sizeof_short == 4
  rconf.set('RINT32_TYPE', 'short')
  rconf.set('RINT32_MODIFIER', '"h"')
  rconf.set('RINT32_FMT', '"hi"')
  rconf.set('RUINT32_FMT', '"hu"')
elif sizeof_int == 4
  rconf.set('RINT32_TYPE', 'int')
  rconf.set('RINT32_MODIFIER', '""')
  rconf.set('RINT32_FMT', '"i"')
  rconf.set('RUINT32_FMT', '"u"')
elif sizeof_long == 4
  rconf.set('RINT32_TYPE', 'long')
  rconf.set('RINT32_MODIFIER', '"l"')
  rconf.set('RINT32_FMT', '"li"')
  rconf.set('RUINT32_FMT', '"lu"')
else
  error('No 32bit type found')
endif

if sizeof_int == 8
  rconf.set('RINT64_TYPE', 'int')
  rconf.set('RINT64_MODIFIER', '""')
  rconf.set('RINT64_FMT', '"i"')
  rconf.set('RUINT64_FMT', '"u"')
  rconf.set('RINT64_CONST', 'val')
  rconf.set('RUINT64_CONST', 'val')
elif sizeof_long == 8
  rconf.set('RINT64_TYPE', 'long')
  rconf.set('RINT64_MODIFIER', '"l"')
  rconf.set('RINT64_FMT', '"li"')
  rconf.set('RUINT64_FMT', '"lu"')
  rconf.set('RINT64_CONST', 'val##L')
  rconf.set('RUINT64_CONST', 'val##UL')
elif sizeof_longlong == 8
  rconf.set('RINT64_TYPE', 'long long')
  rconf.set('RINT64_MODIFIER', '"ll"')
  rconf.set('RINT64_FMT', '"lli"')
  rconf.set('RUINT64_FMT', '"llu"')
  rconf.set('RINT64_CONST', 'val##LL')
  rconf.set('RUINT64_CONST', 'val##ULL')
else
  error('No 64bit type found')
endif

if sizeof_size_t == sizeof_short
  rconf.set('RSIZE_TYPE', 'hosr')
  rconf.set('RSIZE_MODIFIER', '"h"')
  rconf.set('RSIZE_FMT', '"hu"')
  rconf.set('RSSIZE_FMT', '"hi"')
  rconf.set('RLIB_SIZE_TYPE', 'RUSHORT')
  rconf.set('RLIB_SSIZE_TYPE', 'RSHORT')
elif sizeof_size_t == sizeof_int
  rconf.set('RSIZE_TYPE', 'int')
  rconf.set('RSIZE_MODIFIER', '""')
  rconf.set('RSIZE_FMT', '"u"')
  rconf.set('RSSIZE_FMT', '"i"')
  rconf.set('RLIB_SIZE_TYPE', 'RUINT')
  rconf.set('RLIB_SSIZE_TYPE', 'RINT')
elif sizeof_size_t == sizeof_long
  rconf.set('RSIZE_TYPE', 'long')
  rconf.set('RSIZE_MODIFIER', '"l"')
  rconf.set('RSIZE_FMT', '"lu"')
  rconf.set('RSSIZE_FMT', '"li"')
  rconf.set('RLIB_SIZE_TYPE', 'RULONG')
  rconf.set('RLIB_SSIZE_TYPE', 'RLONG')
elif sizeof_size_t == sizeof_longlong
  rconf.set('RSIZE_TYPE', 'long long')
  rconf.set('RSIZE_MODIFIER', '"ll"')
  rconf.set('RSIZE_FMT', '"llu"')
  rconf.set('RSSIZE_FMT', '"lli"')
  rconf.set('RLIB_SIZE_TYPE', 'RUINT64')
  rconf.set('RLIB_SSIZE_TYPE', 'RINT64')
else
  error('No size_t type found')
endif

if sizeof_void_p == sizeof_int
  rconf.set('RINTPTR_TYPE', 'int')
  rconf.set('RINTPTR_MODIFIER', '""')
  rconf.set('RINTPTR_FMT', '"i"')
  rconf.set('RUINTPTR_FMT', '"u"')
  rconf.set('RINTMAX_TYPE', 'int')
  rconf.set('RINTMAX_MODIFIER', '""')
  rconf.set('RINTMAX_FMT', '"i"')
  rconf.set('RUINTMAX_FMT', '"u"')
  rconf.set('RLIB_UINTMAX_TYPE', 'RUINT')
  rconf.set('RLIB_INTMAX_TYPE', 'RINT')
elif sizeof_void_p == sizeof_long
  rconf.set('RINTPTR_TYPE', 'long')
  rconf.set('RINTPTR_MODIFIER', '"l"')
  rconf.set('RINTPTR_FMT', '"li"')
  rconf.set('RUINTPTR_FMT', '"lu"')
  rconf.set('RINTMAX_TYPE', 'long')
  rconf.set('RINTMAX_MODIFIER', '"l"')
  rconf.set('RINTMAX_FMT', '"li"')
  rconf.set('RUINTMAX_FMT', '"lu"')
  rconf.set('RLIB_UINTMAX_TYPE', 'RULONG')
  rconf.set('RLIB_INTMAX_TYPE', 'RLONG')
elif sizeof_void_p == sizeof_longlong
  rconf.set('RINTPTR_TYPE', 'long long')
  rconf.set('RINTPTR_MODIFIER', '"I64"')
  rconf.set('RINTPTR_FMT', '"I64i"')
  rconf.set('RUINTPTR_FMT', '"I64u"')
  rconf.set('RINTMAX_TYPE', 'long long')
  rconf.set('RINTMAX_MODIFIER', '"I64"')
  rconf.set('RINTMAX_FMT', '"I64i"')
  rconf.set('RUINTMAX_FMT', '"I64u"')
  rconf.set('RLIB_UINTMAX_TYPE', 'RUINT64')
  rconf.set('RLIB_INTMAX_TYPE', 'RINT64')
else
  error('No ptr value type found')
endif

rconf.set('RLIB_SIZEOF_VOID_P', sizeof_void_p)
rconf.set('RLIB_SIZEOF_INT', sizeof_int)
rconf.set('RLIB_SIZEOF_LONG', sizeof_long)
rconf.set('RLIB_SIZEOF_INTMAX', sizeof_void_p)
rconf.set('RLIB_SIZEOF_SIZE_T', sizeof_size_t)

# LIBS
# Need to improve thread detection, Mesonbuilds attempt at making thread lib
# build integration easy is flawed.
if host_machine.system() != 'bare'
  libthread = dependency('threads')
else
  libthread = dependency('', required: false)
endif
libm = cc.find_library('m', required : false)
libdl = cc.find_library('dl', required : false)
librt = cc.find_library('rt', required : false)


# HEADERS
req_headers = [
  'stdio.h',
  'stdlib.h',
  'stdarg.h',
  'limits.h',
  'float.h',
  'string.h',
]
check_headers = [
  'unistd.h',
  'alloca.h',
  'dlfcn.h',
  'link.h',
  'sched.h',
  'fcntl.h',
  'poll.h',
  'pthread.h',
  'signal.h',
  'netdb.h',
  'arpa/inet.h',
  'netinet/in.h',
  'sys/types.h',
  'sys/mman.h',
  'sys/socket.h',
  'sys/ioctl.h',
  'sys/select.h',
  'sys/sysctl.h',
  'sys/stat.h',
  'sys/time.h',
  'sys/wait.h',
  'sys/epoll.h',
  'sys/event.h',
]

if host_machine.system() == 'linux'
  check_headers += [
    'sys/eventfd.h',
    'sys/prctl.h',
    'sys/sysinfo.h',
  ]
elif host_machine.system() == 'darwin'
  check_headers += [
    'mach/clock.h',
    'mach/thread_policy.h',
    'mach/mach_time.h',
  ]
endif

check_funcs = [
  # unistd
  [ 'alarm', 'unistd.h' ],
  [ 'lseek', 'unistd.h' ],
  [ 'lseek64', 'unistd.h' ],
  [ 'access', 'unistd.h' ],
  [ 'pipe', 'unistd.h' ],
  [ 'pipe2', 'unistd.h' ],
  # sys/stat
  [ 'mkdir', 'sys/stat.h' ],
  [ 'stat', 'sys/stat.h' ],
  [ 'lstat', 'sys/stat.h' ],
  [ 'fstat', 'sys/stat.h' ],
  # string
  [ 'stpcpy', 'string.h' ],
  [ 'stpncpy', 'string.h' ],
  [ 'strcasecmp', 'string.h' ],
  [ 'strncasecmp', 'string.h' ],
  [ 'strnstr', 'string.h' ],
  [ 'memrchr', 'string.h' ],
  # stdio
  [ 'printf', 'stdio.h' ],
  [ 'fprintf', 'stdio.h' ],
  [ 'sprintf', 'stdio.h' ],
  [ 'vprintf', 'stdio.h' ],
  [ 'vfprintf', 'stdio.h' ],
  [ 'vsprintf', 'stdio.h' ],
  [ 'snprintf', 'stdio.h' ],
  [ 'vsnprintf', 'stdio.h' ],
  [ 'asprintf', 'stdio.h' ],
  [ 'vasprintf', 'stdio.h' ],
  [ '_vscprintf', 'stdio.h' ],
  # time
  [ 'timer_create', 'time.h' ],
  [ 'clock_gettime', 'time.h' ],
  [ 'setitimer', 'sys/time.h' ],
  # arpa/inet
  [ 'inet_aton', 'arpa/inet.h' ],
  [ 'inet_pton', 'arpa/inet.h' ],
  [ 'inet_ntop', 'arpa/inet.h' ],
  # other
  [ 'fcntl', 'fcntl.h' ],
  [ 'ioctl', 'sys/ioctl.h' ],
  [ 'mmap', 'sys/mman.h' ],
  [ 'sysctlbyname', 'sys/sysctl.h' ],
  [ 'kqueue', 'sys/event.h' ],
  [ 'epoll_ctl', 'sys/epoll.h' ],
  [ 'eventfd', 'sys/eventfd.h' ],
  [ 'gettid', 'sys/types.h' ],
  [ 'poll', 'poll.h' ],
  [ 'ppoll', 'poll.h' ],
  [ 'select', 'sys/select.h' ],
  [ 'sigaction', 'signal.h' ],
  [ 'sigaltstack', 'signal.h' ],
]
if host_machine.system() == 'windows'
  check_funcs += [
    [ '_stricmp', 'string.h' ],
    [ '_strnicmp', 'string.h' ],
  ]
endif

foreach h : req_headers
  if cc.has_header(h)
    conf.set('HAVE_' + h.underscorify().to_upper(), 1)
  else
    error('missing ' + h)
  endif
endforeach

foreach h : check_headers
  if cc.has_header(h)
    conf.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach

foreach f : check_funcs
  if cc.has_function(f[0], prefix : '#define _GNU_SOURCE\n#include <@0@>'.format(f[1]))
    conf.set('HAVE_' + f[0].underscorify().to_upper(), 1)
  endif
endforeach

if conf.has('HAVE_ALLOCA_H')
  rconf.set('RLIB_HAVE_ALLOCA_H',     1)
endif

if conf.has('HAVE_DLFCN_H')
  dl_prefix = '''#define _GNU_SOURCE 1
    #include <dlfcn.h>
    '''
  if cc.has_function('dlinfo', prefix : dl_prefix, dependencies : libdl)
    conf.set('HAVE_DLINFO', 1)
  endif
  if cc.has_function('dladdr', prefix : dl_prefix, dependencies : libdl)
    conf.set('HAVE_DLADDR', 1)
  endif
endif

if conf.has('HAVE_PTHREAD_H')
  pthread_prefix = '''#define _GNU_SOURCE 1
    #include <pthread.h>
    '''

  if cc.has_function('pthread_getname_np', prefix : pthread_prefix, args : '-pthread')
    conf.set('HAVE_PTHREAD_GETNAME_NP', 1)
  endif

  pthread_setname_np_with_tid_code = '''
    int main(int argc, char **argv) {
      (void)argc; (void)argv;
      pthread_setname_np (0, "test");
      return 0;
    }
    '''
  if cc.compiles(pthread_prefix + pthread_setname_np_with_tid_code, args : '-pthread')
    conf.set('HAVE_PTHREAD_SETNAME_NP_WITH_TID', 1)
  endif

  pthread_setname_np_without_tid_code = '''
    int main(int argc, char **argv) {
      (void)argc; (void)argv;
      pthread_setname_np ("test");
      return 0;
    }
    '''
  if cc.compiles(pthread_prefix + pthread_setname_np_without_tid_code, args : '-pthread')
    conf.set('HAVE_PTHREAD_SETNAME_NP_WITHOUT_TID', 1)
  endif

  if cc.has_function('pthread_getthreadid_np', prefix : pthread_prefix, args : '-pthread')
    conf.set('HAVE_PTHREAD_GETTHREADID_NP', 1)
  endif
  if cc.has_function('pthread_threadid_np', prefix : pthread_prefix, args : '-pthread')
    conf.set('HAVE_PTHREAD_THREADID_NP', 1)
  endif

  if cc.has_function('pthread_getaffinity_np', prefix : pthread_prefix, args : '-pthread')
    conf.set('HAVE_PTHREAD_GETAFFINITY_NP', 1)
  endif
  if cc.has_function('pthread_setaffinity_np', prefix : pthread_prefix, args : '-pthread')
    conf.set('HAVE_PTHREAD_SETAFFINITY_NP', 1)
  endif
  if cc.has_function('pthread_attr_setaffinity_np', prefix : pthread_prefix, args : '-pthread')
    conf.set('HAVE_PTHREAD_ATTR_SETAFFINITY_NP', 1)
  endif
endif

if conf.has('HAVE_SIGNAL_H')
  if cc.has_member('siginfo_t', 'si_status', prefix : '#include <signal.h>')
    conf.set('HAVE_SIGINFO_T_SI_STATUS', 1)
  endif

  if cc.has_member('struct sigaction', 'sa_sigaction', prefix : '#include <signal.h>')
    conf.set('HAVE_SIGACTION_SA_SIGACTION', 1)
  endif
endif
if cc.has_header_symbol('signal.h', 'sys_siglist')
  conf.set('HAVE_SYS_SIGLIST', 1)
endif

rconf_defines = []
if host_machine.system() == 'windows'
  socket_h = '#include <winsock2.h>'
  netdb_h = '#include <ws2tcpip.h>'
  poll_h = '#include <winsock2.h>'
  rconf_defines += [
    [ 'R_AF_UNIX', '1' ],
    [ 'R_AF_BLUETOOTH', cc.get_define('AF_BTH', prefix : socket_h) ],
  ]
else
  if conf.has('HAVE_SYS_SOCKET_H')
    socket_h = '#include <sys/socket.h>'
  else
    socket_h = ''
  endif

  if conf.has('HAVE_NETDB_H')
    netdb_h = '#include <netdb.h>'
  else
    netdb_h = ''
  endif

  poll_h = '#include <poll.h>'

  rconf_defines += [
    [ 'R_AF_UNIX',      cc.get_define('AF_UNIX',      prefix : socket_h), '1' ],
    [ 'R_AF_BLUETOOTH', cc.get_define('AF_BLUETOOTH', prefix : socket_h), '31' ],
  ]
endif

rconf_defines += [
  [ 'R_AF_INET',        cc.get_define('AF_INET',  prefix : socket_h), '2' ],
  [ 'R_AF_INET6',       cc.get_define('AF_INET6', prefix : socket_h), '10' ],
  [ 'R_AF_IRDA',        cc.get_define('AF_IRDA',  prefix : socket_h), '23' ],
]

rconf_defines += [
  [ 'R_AI_PASSIVE',     cc.get_define('AI_PASSIVE',     prefix : netdb_h), '0' ],
  [ 'R_AI_CANONNAME',   cc.get_define('AI_CANONNAME',   prefix : netdb_h), '0' ],
  [ 'R_AI_NUMERICHOST', cc.get_define('AI_NUMERICHOST', prefix : netdb_h), '0' ],
  [ 'R_AI_V4MAPPED',    cc.get_define('AI_V4MAPPED',    prefix : netdb_h), '0' ],
  [ 'R_AI_ALL',         cc.get_define('AI_ALL',         prefix : netdb_h), '0' ],
  [ 'R_AI_ADDRCONFIG',  cc.get_define('AI_ADDRCONFIG',  prefix : netdb_h), '0' ],
]

rconf_defines += [
  [ 'R_IO_IN',   cc.get_define('POLLIN',   prefix: poll_h),  '1' ],
  [ 'R_IO_OUT',  cc.get_define('POLLOUT',  prefix: poll_h),  '4' ],
  [ 'R_IO_PRI',  cc.get_define('POLLPRI',  prefix: poll_h),  '2' ],
  [ 'R_IO_ERR',  cc.get_define('POLLERR',  prefix: poll_h),  '8' ],
  [ 'R_IO_HUP',  cc.get_define('POLLHUP',  prefix: poll_h), '16' ],
  [ 'R_IO_NVAL', cc.get_define('POLLNVAL', prefix: poll_h), '32' ],
]

foreach d : rconf_defines
  rconf.set(d[0], d[1].strip() != '' ? d[1] : d[2])
endforeach

configure_file(input : 'config.h.meson', output : 'config.h', configuration : conf)

###############################################################################
# options
# FIXME: disable by meson build options
###############################################################################
rlib_have_threads = get_option('enable_threads') and libthread.found()
rlib_have_modules = get_option('enable_modules') and (host_machine.system() == 'windows' or libdl.found())
rlib_have_signals = get_option('enable_signals') and conf.has('HAVE_SIGNAL_H')
rlib_have_files   = get_option('enable_files') and host_machine.system() != 'bare'
rlib_have_sockets = get_option('enable_sockets') and (host_machine.system() == 'windows' or conf.has('HAVE_SYS_SOCKET_H'))

if rlib_have_threads
  rconf.set('RLIB_HAVE_THREADS', 1)
endif
if rlib_have_modules
  rconf.set('RLIB_HAVE_MODULES', 1)
endif
if rlib_have_signals
  rconf.set('RLIB_HAVE_SIGNALS', 1)
endif
if rlib_have_files
  rconf.set('RLIB_HAVE_FILES', 1)
endif
if rlib_have_sockets
  rconf.set('RLIB_HAVE_SOCKETS', 1)
endif

###############################################################################
# subdirs
###############################################################################
subdir('rlib')
subdir('test')
subdir('docs')
subdir('example')
subdir('bench')

