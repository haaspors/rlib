#!/usr/bin/env python
#encoding: utf-8

APPNAME = 'rlib'
VERSION = '0.0.1'
APIVERSION = '0.1'

top = '.'
out = '_build_'

DBGVAR = 'debug'
RELVAR = 'release'
DEFVAR = RELVAR
VARIANTS = [ DBGVAR, RELVAR ]

def options(opt):
    opt.load('compiler_c')
    opt.add_option('--variant',
            action='store', dest='variant', default=DEFVAR,
            help='use variant %r (defualt: %s)' % (VARIANTS, DEFVAR))
    opt.add_option('-d', '--debug',
            action='store_const', const=DBGVAR, dest='variant',
            help='use the debug variant')

def configure(cfg):
    cfg.load('compiler_c')

    # COMMON (for all variants)
    if cfg.env['CC_NAME'] == 'msvc':
        cfg.env.CPPFLAGS += ['/Zi', '/FS'] #, '/Wall']
    else:
        cfg.env.CPPFLAGS += ['-Wall', '-Werror', '-Wextra']
        cfg.env.CFLAGS += ['-fvisibility=hidden']

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

def buildall(ctx):
    from waflib.Options import commands
    for var in VARIANTS:
        commands.insert(0, 'build_' + var)

def build(bld):
    if not bld.variant:
        bld.fatal('No variant specified')

def init(ctx):
    from waflib.Build import BuildContext, CleanContext, InstallContext, UninstallContext
    from waflib.Options import options

    for y in (BuildContext, CleanContext, InstallContext, UninstallContext):
        name = y.__name__.replace('Context','').lower()
        class tmp(y):
            cmd = name
            variant = options.variant

        for var in VARIANTS:
            class tmp(y):
                cmd = name + '_' + var
                variant = var

