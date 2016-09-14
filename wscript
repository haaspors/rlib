#!/usr/bin/env python
#encoding: utf-8

import os

# Bring in waf tools
import tools.waf.conf

LIBNAME = 'rlib'
VERSION = '1.0.0'
APIVERSION = '1.0'

SHLIBNAME = LIBNAME
STLIBNAME = LIBNAME + 'st'

top = '.'
out = '_build_'

DBGVAR = 'debug'
RELVAR = 'release'
DEFVAR = RELVAR
VARIANTS = [ DBGVAR, RELVAR ]

def options(opt):
    opt.load('compiler_c')
    opt.load('test', tooldir='tools/waf')
    opt.load('bench', tooldir='tools/waf')

    grp = opt.add_option_group('configure options')
    grp.add_option('--no-thread',
            action='store_true', dest='nothread',
            help='Don\'t support threads')
    grp.add_option('--no-signal',
            action='store_true', dest='nosignal',
            help='Don\'t support signals')
    grp.add_option('--no-fs',
            action='store_true', dest='nofs',
            help='Don\'t support files/file system')

    grp = opt.add_option_group('build and install options')
    grp.add_option('--variant',
            action='store', dest='variant', default=DEFVAR,
            help='use variant %r (defualt: %s)' % (VARIANTS, DEFVAR))
    grp.add_option('-d', '--debug',
            action='store_const', const=DBGVAR, dest='variant',
            help='use the debug variant')
    grp.add_option('--no-bin',
            action='store_true', dest='nobin',
            help='Turn of all building of binaries (examples/tests)')

def configure(cfg):
    cfg.load('compiler_c')
    cfg.load('test', tooldir='tools/waf')
    cfg.load('bench', tooldir='tools/waf')

    configure_options(cfg)

    if not cfg.env.BUILD_SHLIB and not cfg.env.BUILD_STLIB:
        cfg.fatal('not building static nor dynamic linked library')

    ##################################
    # COMMON (for all variants)
    ##################################
    configure_os_arch(cfg)
    configure_headers(cfg)
    configure_libs(cfg)
    configure_sys(cfg)
    configure_string(cfg)
    configure_sizeof(cfg)
    configure_printf(cfg)
    configure_time(cfg)
    configure_threads(cfg)
    configure_signal(cfg)
    configure_fs(cfg)
    configure_networking(cfg)

    if cfg.env.BUILD_SHLIB:
        cfg.env.RLIB_INTERNAL_USE = SHLIBNAME + ' RTEST'
    else:
        cfg.env.RLIB_INTERNAL_USE = STLIBNAME + ' RTEST'

    if cfg.env['CC_NAME'] == 'msvc':
        cfg.env.CPPFLAGS += ['/Zi', '/FS'] #, '/Wall']
    else:
        cfg.env.CPPFLAGS += ['-Wall', '-Werror', '-Wextra']
        cfg.env.CFLAGS += ['-fvisibility=hidden']

    if cfg.env.DEST_BINFMT == 'elf':
        cfg.env.LINKFLAGS_RTEST = ['-Wl,--export-dynamic']

    common_env = cfg.env

    # DEBUG
    cfg.setenv(DBGVAR, env=common_env)
    cfg.env.detach()
    if cfg.env['CC_NAME'] == 'msvc':
        cfg.env.CFLAGS += ['/MDd', '/Od']
        cfg.env.LINKFLAGS += ['/DEBUG']
    else:
        cfg.env.CFLAGS += ['-g']
    cfg.define('DEBUG', 1)
    cfg.write_config_header(DBGVAR+'/config.h')

    # RELEASE
    cfg.setenv(RELVAR, env=common_env)
    cfg.env.detach()
    if cfg.env['CC_NAME'] == 'msvc':
        cfg.env.CFLAGS += ['/MD', '/O2']
    else:
        cfg.env.CFLAGS += ['-O2']
    cfg.define('NDEBUG', 1)
    cfg.write_config_header(RELVAR+'/config.h')

    build_summary(cfg)

def buildall(ctx):
    from waflib.Options import commands
    for var in VARIANTS:
        commands.insert(0, 'build_' + var)

def build(bld):
    if not bld.variant:
        bld.fatal('No variant specified')

    bld(    features    = 'subst',
            source      = 'rlib/rconfig.h.in',
            target      = 'rlib/rconfig.h',
            install_path= '${PREFIX}/include/rlib')

    privlibs = []
    if bld.env.RLIB_MATH_LIBS:
        privlibs.append(bld.env.RLIB_MATH_LIBS)
    if bld.env.RLIB_RT_LIBS:
        privlibs.append(bld.env.RLIB_RT_LIBS)
    if bld.env.RLIB_THREAD_LIBS:
        privlibs.append(bld.env.RLIB_THREAD_LIBS)

    if bld.env.BUILD_SHLIB:
        bld.shlib(
                source      = bld.path.ant_glob('rlib/**/*.c'),
                target      = SHLIBNAME,
                vnum        = APIVERSION,
                includes    = [ '.' ],
                defines     = [ 'RLIB_COMPILATION', 'RLIB_SHLIB' ],
                use         = 'M DL PTHREAD RT KERNEL32 ADVAPI32')
        bld(    features    = 'subst',
                source      = LIBNAME + '.pc.in',
                target      = SHLIBNAME + '.pc',
                NAME        = SHLIBNAME,
                VERSION     = VERSION,
                install_path= '${LIBDIR}/pkgconfig')
    if bld.env.BUILD_STLIB:
        bld.stlib(
                source      = bld.path.ant_glob('rlib/**/*.c'),
                target      = STLIBNAME,
                install_path= '${LIBDIR}',
                includes    = [ '.' ],
                defines     = [ 'RLIB_COMPILATION', 'RLIB_STLIB' ],
                use         = 'M DL PTHREAD RT')
        bld(    features    = 'subst',
                source      = LIBNAME + '.pc.in',
                target      = STLIBNAME + '.pc',
                NAME        = STLIBNAME,
                VERSION     = VERSION,
                RLIB_EXTRA_LIBS = ' '.join(privlibs),
                install_path= '${LIBDIR}/pkgconfig')

    bld.install_files('${PREFIX}/include',
            bld.path.ant_glob('rlib/**/*.h', excl = [ 'rlib/**/*private.h' ]),
            relative_trick=True)

    bld.recurse('bench example test')

def init(ctx):
    from waflib.Build import BuildContext, CleanContext, ListContext, InstallContext, UninstallContext, StepContext
    from tools.waf.test import TestContext
    from tools.waf.bench import BenchContext
    from waflib.Options import options

    for y in (BuildContext, CleanContext, ListContext, InstallContext, UninstallContext, StepContext, TestContext, BenchContext):
        name = y.__name__.replace('Context','').lower()
        class tmp(y):
            cmd = name
            variant = options.variant

        for var in VARIANTS:
            class tmp(y):
                cmd = name + '_' + var
                variant = var

def configure_options(cfg):
    environ = getattr(cfg, 'environ', os.environ)
    cfg.env.BUILD_SHLIB = str2bool(environ.get('BUILD_SHLIB', str(cfg.env.DEST_OS != 'none')))
    cfg.env.BUILD_STLIB = str2bool(environ.get('BUILD_STLIB', 'True'))
    cfg.env.BUILD_BIN = str2bool(environ.get('BUILD_BIN', str(cfg.env.DEST_OS != 'none')))
    if getattr(cfg.options, 'nobin'):
        cfg.env.BUILD_BIN = False
    if getattr(cfg.options, 'nothread'):
        cfg.env.NOTHREAD = True
    if getattr(cfg.options, 'nosignal'):
        cfg.env.NOSIGNAL = True
    if getattr(cfg.options, 'nofs'):
        cfg.env.NOFS = True

def configure_os_arch(cfg):
    cfg.start_msg('Checking dest/host OS')
    if cfg.env.DEST_OS == 'win32':
        cfg.env.RLIB_OS = 'R_OS_WIN32'
    elif cfg.env.DEST_OS == 'none':
        cfg.env.RLIB_OS = 'R_OS_NONE'
    else:
        cfg.env.RLIB_OS = 'R_OS_UNIX'
    if cfg.env.DEST_OS == 'linux':
        cfg.env.RLIB_OS_EXTRA = '#define R_OS_LINUX              1'
    elif cfg.env.DEST_OS == 'darwin':
        cfg.env.RLIB_OS_EXTRA = '#define R_OS_DARWIN             1'
    elif cfg.env.DEST_OS == 'freebsd':
        cfg.env.RLIB_OS_EXTRA = '#define R_OS_FREEBSD            1'
    elif cfg.env.DEST_OS == 'netbsd':
        cfg.env.RLIB_OS_EXTRA = '#define R_OS_NETBSD             1'
    elif cfg.env.DEST_OS == 'openbsd':
        cfg.env.RLIB_OS_EXTRA = '#define R_OS_OPENBSD            1'
    elif cfg.env.DEST_OS == 'sunos':
        cfg.env.RLIB_OS_EXTRA = '#define R_OS_SOLARIS            1'
    cfg.end_msg(cfg.env.DEST_OS, 'CYAN')
    cfg.start_msg('Checking dest/host CPU/ARCH')
    archcolor = 'CYAN'
    if cfg.env.DEST_CPU in ['x86_64', 'amd64', 'x64']:
        cfg.env.RLIB_ARCH = 'R_ARCH_X86_64'
    elif cfg.env.DEST_CPU == 'x86':
        cfg.env.RLIB_ARCH = 'R_ARCH_X86'
    elif cfg.env.DEST_CPU == 'ia':
        cfg.env.RLIB_ARCH = 'R_ARCH_IA64'
    elif cfg.env.DEST_CPU == 'arm':
        cfg.env.RLIB_ARCH = 'R_ARCH_ARM'
    elif cfg.env.DEST_CPU == 'thumb':
        cfg.env.RLIB_ARCH = 'R_ARCH_THUMB'
    elif cfg.env.DEST_CPU == 'aarch64':
        cfg.env.RLIB_ARCH = 'R_ARCH_AARCH64'
    elif cfg.env.DEST_CPU == 'mips':
        cfg.env.RLIB_ARCH = 'R_ARCH_MIPS'
    elif cfg.env.DEST_CPU == 'sparc':
        cfg.env.RLIB_ARCH = 'R_ARCH_SPARC'
    elif cfg.env.DEST_CPU == 'alpha':
        cfg.env.RLIB_ARCH = 'R_ARCH_ALPHA'
    elif cfg.env.DEST_CPU == 'powerpc':
        cfg.env.RLIB_ARCH = 'R_ARCH_POWERPC'
    elif cfg.env.DEST_CPU == 'xtensa':
        cfg.env.RLIB_ARCH = 'R_ARCH_XTENSA'
    else:
        cfg.env.RLIB_ARCH = 'R_ARCH_UNKNOWN'
        archcolor = 'RED'
    cfg.end_msg(cfg.env.DEST_CPU, archcolor)

def configure_headers(cfg):
    cfg.multicheck(
            {'header_name':'stdio.h'},
            {'header_name':'stdlib.h'},
            {'header_name':'stdarg.h'},
            {'header_name':'limits.h'},
            {'header_name':'float.h'},
            {'header_name':'string.h'},
            msg = 'Checking for standard headers')

    if cfg.check(header_name='alloca.h', mandatory=False):
        cfg.env.RLIB_DEFINE_HAVE_ALLOCA_H = '#define RLIB_HAVE_ALLOCA_H      1'
    else:
        cfg.env.RLIB_DEFINE_HAVE_ALLOCA_H = '/* #undef RLIB_HAVE_ALLOCA_H */'

    if cfg.check(header_name='dlfcn.h', mandatory=False):
        if cfg.check(lib='dl'):
            cfg.env.RLIB_DL_LIBS = '-ldl'

    cfg.check(header_name='sched.h', mandatory=False)
    cfg.check(header_name='fcntl.h', mandatory=False)
    cfg.check(header_name='arpa/inet.h', mandatory=False)
    cfg.check(header_name='netinet/in.h', mandatory=False)
    cfg.check(header_name='sys/ioctl.h', mandatory=False)
    cfg.check(header_name='sys/socket.h', mandatory=False)
    cfg.check(header_name='sys/sysctl.h', mandatory=False)
    if cfg.env.DEST_OS == 'linux':
        cfg.check(header_name='sys/eventfd.h')
        cfg.check(header_name='sys/prctl.h')
        cfg.check(header_name='sys/sysinfo.h')

    cfg.check(header_name='sys/time.h', mandatory=False)
    cfg.check(header_name='sys/types.h', mandatory=False)
    if cfg.env.DEST_OS == 'darwin':
        cfg.check(header_name='mach/clock.h')
        cfg.check(header_name='mach/thread_policy.h')
        cfg.check(header_name='mach/mach_time.h')

def configure_libs(cfg):
    if not cfg.env.DEST_OS == 'win32':
        if cfg.check(lib='m', mandatory=False):
            cfg.env.RLIB_MATH_LIBS = '-lm'
        if cfg.check(lib='rt', mandatory=False):
            cfg.env.RLIB_RT_LIBS = '-lrt'
    else:
        cfg.check_libs_msvc('kernel32 advapi32')

def configure_sys(cfg):
    cfg.check_cc(function_name='sysctlbyname',
            header_name="sys/sysctl.h", mandatory=False)
    cfg.check_cc(function_name='ioctl',
            header_name="sys/ioctl.h", mandatory=False)
    cfg.check_cc(function_name='fcntl',
            header_name="fcntl.h", mandatory=False)
    cfg.check_cc(function_name='eventfd',
            header_name="sys/eventfd.h", mandatory=False)
    cfg.check_cc(function_name='kqueue',
            header_name="sys/event.h", mandatory=False)
    cfg.check_cc(function_name='epoll_ctl',
            define_name="HAVE_EPOLL",
            header_name="sys/epoll.h", mandatory=False)

def configure_string(cfg):
    cfg.check_cc(function_name='stpcpy',
            header_name="string.h", mandatory=False)
    cfg.check_cc(function_name='stpncpy',
            header_name="string.h", mandatory=False)
    cfg.check_cc(function_name='strnstr',
            header_name="string.h", mandatory=False)

def configure_printf(cfg):
    funcs = ['printf', 'fprintf', 'sprintf',
             'vprintf', 'vfprintf', 'vsprintf',
             'snprintf', 'vsnprintf',
             'asprintf', 'vasprintf',
             '_vscprintf']
    for f in funcs:
        cfg.check_cc(function_name=f,header_name="stdio.h", mandatory=False)

def configure_time(cfg):
    if cfg.env.DEST_OS not in [ 'darwin', 'win32']:
        cfg.check_cc(function_name='clock_gettime',
                header_name="time.h", lib='rt', mandatory=False)


SNIP_PTHREAD_CALL = '''
#include <pthread.h>

int main(int argc, char **argv) {
  (void)argc; (void)argv;
  %s;
  return 0;
}
'''
def configure_threads(cfg):
    if cfg.env.NOTHREAD:
        cfg.env.RLIB_DEFINE_HAVE_THREADS = '/* #undef RLIB_HAVE_THREADS */'
        return

    cfg.env.RLIB_DEFINE_HAVE_THREADS = '#define RLIB_HAVE_THREADS     1'
    cfg.check_cc(function_name='gettid',
            header_name="sys/types.h", mandatory=False)
    if cfg.check(header_name='pthread.h', mandatory=False):
        cfg.env.RLIB_THREAD_LIBS = '-pthread'
        cfg.check_cc(function_name='pthread_getname_np', defines=['_GNU_SOURCE=1'],
                header_name="pthread.h", lib='pthread', mandatory=False)
        cfg.check_cc(
                fragment=SNIP_PTHREAD_CALL % 'pthread_setname_np (0, "test")',
                define_name="HAVE_PTHREAD_SETNAME_NP_WITH_TID",
                msg='Checking for pthread_setname_np (pthread_t, const char*)',
                defines=['_GNU_SOURCE=1'], lib='pthread', mandatory=False)
        cfg.check_cc(
                fragment=SNIP_PTHREAD_CALL % 'pthread_setname_np ("test")',
                msg='Checking for pthread_setname_np (const char*)',
                define_name="HAVE_PTHREAD_SETNAME_NP_WITHOUT_TID",
                defines=['_GNU_SOURCE=1'], lib='pthread', mandatory=False)
        cfg.check_cc(function_name='pthread_getthreadid_np', defines=['_GNU_SOURCE=1'],
                header_name="pthread.h", lib='pthread', mandatory=False)
        cfg.check_cc(function_name='pthread_threadid_np', defines=['_GNU_SOURCE=1'],
                header_name="pthread.h", lib='pthread', mandatory=False)
        cfg.check_cc(function_name='pthread_getaffinity_np', defines=['_GNU_SOURCE=1'],
                header_name="pthread.h", lib='pthread', mandatory=False)
        cfg.check_cc(function_name='pthread_setaffinity_np', defines=['_GNU_SOURCE=1'],
                header_name="pthread.h", lib='pthread', mandatory=False)
        cfg.check_cc(function_name='pthread_attr_setaffinity_np', defines=['_GNU_SOURCE=1'],
                header_name="pthread.h", lib='pthread', mandatory=False)

def configure_signal(cfg):
    if cfg.env.NOSIGNAL:
        cfg.env.RLIB_DEFINE_HAVE_SIGNALS = '/* #undef RLIB_HAVE_SIGNALS */'
        return

    cfg.env.RLIB_DEFINE_HAVE_SIGNALS = '#define RLIB_HAVE_SIGNALS     1'
    if not cfg.env.DEST_OS == 'win32':
        cfg.check_cc(function_name='timer_create', lib='rt',
                header_name="time.h", mandatory=False)
        cfg.check_cc(function_name='setitimer',
                header_name="sys/time.h", mandatory=False)
        cfg.check_cc(function_name='alarm',
                header_name="unistd.h", mandatory=False)

def configure_fs(cfg):
    if cfg.env.NOFS:
        cfg.env.RLIB_DEFINE_HAVE_FILES = '/* #undef RLIB_HAVE_FILES */'
    else:
        cfg.env.RLIB_DEFINE_HAVE_FILES = '#define RLIB_HAVE_FILES     1'

def configure_networking(cfg):
    cfg.check_cc(function_name='inet_pton',
            header_name="arpa/inet.h", mandatory=False)
    cfg.check_cc(function_name='inet_ntop',
            header_name="arpa/inet.h", mandatory=False)
    if cfg.env.DEST_OS == 'win32':
        cfg.env.R_AF_UNIX       = 1;
        cfg.env.R_AF_INET       = cfg.compute_int('AF_INET', header_name='winsock2.h', guess=2) or 2;
        cfg.env.R_AF_INET6      = cfg.compute_int('AF_INET6', header_name='winsock2.h', guess=23) or 'R_SOCKET_FAMILY_NONE';
        cfg.env.R_AF_IRDA       = cfg.compute_int('AF_IRDA', header_name='winsock2.h', guess=26) or 'R_SOCKET_FAMILY_NONE';
        cfg.env.R_AF_BLUETOOTH  = cfg.compute_int('AF_BTH', header_name='winsock2.h', guess=32) or 'R_SOCKET_FAMILY_NONE';
    else:
        cfg.env.R_AF_UNIX       = cfg.compute_int('AF_UNIX', header_name='sys/socket.h', guess=1) or 1;
        cfg.env.R_AF_INET       = cfg.compute_int('AF_INET', header_name='sys/socket.h', guess=2) or 2;
        cfg.env.R_AF_INET6      = cfg.compute_int('AF_INET6', header_name='sys/socket.h', guess=10) or 'R_SOCKET_FAMILY_NONE';
        cfg.env.R_AF_IRDA       = cfg.compute_int('AF_IRDA', header_name='sys/socket.h', guess=23) or 'R_SOCKET_FAMILY_NONE';
        cfg.env.R_AF_BLUETOOTH  = cfg.compute_int('AF_BLUETOOTH', header_name='sys/socket.h', guess=31) or 'R_SOCKET_FAMILY_NONE';


def configure_sizeof(cfg):
    sizeof_short = cfg.check_sizeof('short', guess=2)
    sizeof_int = cfg.check_sizeof('int', guess=4)
    sizeof_long = cfg.check_sizeof('long', guess=8)
    sizeof_longlong = cfg.check_sizeof('long long', guess=8)
    sizeof_size_t = cfg.check_sizeof('size_t', guess=sizeof_longlong)
    sizeof_void_p = cfg.check_sizeof('void*', guess=sizeof_size_t)

    if sizeof_short == 2:
        cfg.env.RINT16_TYPE = 'short'
        cfg.env.RINT16_MODIFIER = '"h"'
        cfg.env.RINT16_FMT = '"hi"'
        cfg.env.RUINT16_FMT = '"hu"'
    elif sizeof_int == 2:
        cfg.env.RINT16_TYPE = 'int'
        cfg.env.RINT16_MODIFIER = '""'
        cfg.env.RINT16_FMT = '"i"'
        cfg.env.RUINT16_FMT = '"u"'
    if sizeof_short == 4:
        cfg.env.RINT32_TYPE = 'short'
        cfg.env.RINT32_MODIFIER = '"h"'
        cfg.env.RINT32_FMT = '"hi"'
        cfg.env.RUINT32_FMT = '"hu"'
    elif sizeof_int == 4:
        cfg.env.RINT32_TYPE = 'int'
        cfg.env.RINT32_MODIFIER = '""'
        cfg.env.RINT32_FMT = '"i"'
        cfg.env.RUINT32_FMT = '"u"'
    elif sizeof_long == 4:
        cfg.env.RINT32_TYPE = 'long'
        cfg.env.RINT32_MODIFIER = '"l"'
        cfg.env.RINT32_FMT = '"li"'
        cfg.env.RUINT32_FMT = '"lu"'
    if sizeof_int == 8:
        cfg.env.RINT64_TYPE = 'int'
        cfg.env.RINT64_MODIFIER = '""'
        cfg.env.RINT64_FMT = '"i"'
        cfg.env.RUINT64_FMT = '"u"'
        cfg.env.RINT64_CONST = 'val'
        cfg.env.RUINT64_CONST = 'val'
    elif sizeof_long == 8:
        cfg.env.RINT64_TYPE = 'long'
        cfg.env.RINT64_MODIFIER = '"l"'
        cfg.env.RINT64_FMT = '"li"'
        cfg.env.RUINT64_FMT = '"lu"'
        cfg.env.RINT64_CONST = 'val##L'
        cfg.env.RUINT64_CONST = 'val##UL'
    elif sizeof_longlong == 8:
        cfg.env.RINT64_TYPE = 'long long'
        cfg.env.RINT64_MODIFIER = '"ll"'
        cfg.env.RINT64_FMT = '"lli"'
        cfg.env.RUINT64_FMT = '"llu"'
        cfg.env.RINT64_CONST = 'val##LL'
        cfg.env.RUINT64_CONST = 'val##ULL'

    if sizeof_size_t == sizeof_short:
        cfg.env.RSIZE_TYPE = 'short'
        cfg.env.RSIZE_MODIFIER = '"h"'
        cfg.env.RSIZE_FMT = '"hu"'
        cfg.env.RSSIZE_FMT = '"hi"'
        cfg.env.RLIB_SIZE_TYPE = 'RUSHORT'
        cfg.env.RLIB_SSIZE_TYPE = 'RSHORT'
    elif sizeof_size_t == sizeof_int:
        cfg.env.RSIZE_TYPE = 'int'
        cfg.env.RSIZE_MODIFIER = '""'
        cfg.env.RSIZE_FMT = '"u"'
        cfg.env.RSSIZE_FMT = '"i"'
        cfg.env.RLIB_SIZE_TYPE = 'RUINT'
        cfg.env.RLIB_SSIZE_TYPE = 'RINT'
    elif sizeof_size_t == sizeof_long:
        cfg.env.RSIZE_TYPE = 'long'
        cfg.env.RSIZE_MODIFIER = '"l"'
        cfg.env.RSIZE_FMT = '"lu"'
        cfg.env.RSSIZE_FMT = '"li"'
        cfg.env.RLIB_SIZE_TYPE = 'RULONG'
        cfg.env.RLIB_SSIZE_TYPE = 'RLONG'
    elif sizeof_size_t == sizeof_longlong:
        cfg.env.RSIZE_TYPE = 'long long'
        cfg.env.RSIZE_MODIFIER = '"I64"'
        cfg.env.RSIZE_FMT = '"I64u"'
        cfg.env.RSSIZE_FMT = '"I64i"'
        cfg.env.RLIB_SIZE_TYPE = 'RUINT64'
        cfg.env.RLIB_SSIZE_TYPE = 'RINT64'

    if sizeof_void_p == sizeof_int:
        cfg.env.RINTPTR_TYPE = 'int'
        cfg.env.RINTPTR_MODIFIER = '""'
        cfg.env.RINTPTR_FMT = '"i"'
        cfg.env.RUINTPTR_FMT = '"u"'
        cfg.env.RINTMAX_TYPE = 'int'
        cfg.env.RINTMAX_MODIFIER = '""'
        cfg.env.RINTMAX_FMT = '"i"'
        cfg.env.RUINTMAX_FMT = '"u"'
        cfg.env.RLIB_UINTMAX_TYPE = 'RUINT'
        cfg.env.RLIB_INTMAX_TYPE = 'RINT'
    elif sizeof_void_p == sizeof_long:
        cfg.env.RINTPTR_TYPE = 'long'
        cfg.env.RINTPTR_MODIFIER = '"l"'
        cfg.env.RINTPTR_FMT = '"li"'
        cfg.env.RUINTPTR_FMT = '"lu"'
        cfg.env.RINTMAX_TYPE = 'long'
        cfg.env.RINTMAX_MODIFIER = '"l"'
        cfg.env.RINTMAX_FMT = '"li"'
        cfg.env.RUINTMAX_FMT = '"lu"'
        cfg.env.RLIB_UINTMAX_TYPE = 'RULONG'
        cfg.env.RLIB_INTMAX_TYPE = 'RLONG'
    elif sizeof_void_p == sizeof_longlong:
        cfg.env.RINTPTR_TYPE = 'long long'
        cfg.env.RINTPTR_MODIFIER = '"I64"'
        cfg.env.RINTPTR_FMT = '"I64i"'
        cfg.env.RUINTPTR_FMT = '"I64u"'
        cfg.env.RINTMAX_TYPE = 'long long'
        cfg.env.RINTMAX_MODIFIER = '"I64"'
        cfg.env.RINTMAX_FMT = '"I64i"'
        cfg.env.RUINTMAX_FMT = '"I64u"'
        cfg.env.RLIB_UINTMAX_TYPE = 'RUINT64'
        cfg.env.RLIB_INTMAX_TYPE = 'RINT64'

    cfg.env.RLIB_SIZEOF_VOID_P = sizeof_void_p
    cfg.env.RLIB_SIZEOF_INT = sizeof_int
    cfg.env.RLIB_SIZEOF_LONG = sizeof_long
    cfg.env.RLIB_SIZEOF_INTMAX = sizeof_void_p
    cfg.env.RLIB_SIZEOF_SIZE_T = sizeof_size_t

def str2bool(s):
    return not s.lower() in [ 'false', '0', 'n', 'no', 'not']

def build_summary(cfg):
    print('\nBuild summary')
    cfg.msg('Prefix', cfg.env.PREFIX, color='GREEN')
    cfg.msg('Building for dest/host arch', cfg.env.DEST_CPU, color='CYAN')
    cfg.msg('Building for dest/host OS', cfg.env.DEST_OS, color='CYAN')
    build_summary_item(cfg, 'Support threads', not cfg.env.NOTHREAD, 'GREEN', 'RED')
    build_summary_item(cfg, 'Support signals', not cfg.env.NOSIGNAL, 'GREEN', 'RED')
    build_summary_item(cfg, 'Support file system', not cfg.env.NOFS, 'GREEN', 'RED')
    build_summary_item(cfg, 'Building shared library', cfg.env.BUILD_SHLIB)
    build_summary_item(cfg, 'Building static library', cfg.env.BUILD_STLIB)
    build_summary_item(cfg, 'Building binaries', cfg.env.BUILD_BIN)

def build_summary_item(cfg, msg, cond, clryes='BOLD', clrno='YELLOW'):
    cfg.start_msg(msg)
    if cond:
        cfg.end_msg('yes', clryes)
    else:
        cfg.end_msg('no', clrno)

