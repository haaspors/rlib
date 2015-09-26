#!/usr/bin/env python
#encoding: utf-8

"""test.py: Waf Test tools - inspired from waf_unit_test"""

__copyright__       = "Copyright 2015 Haakon Sporsheim <haakon.sporsheim@gmail.com>"
__license__         = "MIT"
__author__          = "Haakon Sporsheim"
__email__           = "haakon.sporsheim@gmail.com"

import os
from waflib.Build import BuildContext
from waflib.TaskGen import feature, after_method, taskgen_method
from waflib.Utils import threading, subprocess
from waflib import Context, Errors, Logs, Utils, Task

class TestContext(BuildContext):
    '''extecutes tests'''
    cmd = 'test'

    def display_output(self):
        if not hasattr(self, 'test_output'): return
        for o in self.test_output:
            Logs.pprint('CYAN', 'Ran \'%r\'' % o[0], ('ret: %r' % o[1]) if o[1] else '')
            if o[3]: Logs.pprint('CYAN', 'err:', '\n'+o[3])
            if o[2]: Logs.pprint('CYAN', 'out:', '\n'+o[2])

    def execute(self, **kw):
        try:
            super(TestContext, self).execute(**kw)
        finally:
            self.display_output()

@feature('test')
@after_method('apply_link')
def perform_test(self):
    """Create the test task."""
    if getattr(self, 'link_task', None):
        self.create_task('test', self.link_task.outputs)

@taskgen_method
def add_test_output(self, output):
    """Gather test output to be properly displayed after build is done"""
    Logs.debug("test: %r", output)
    self.test_output = output
    try:
        self.bld.test_output.append(output)
    except AttributeError:
        self.bld.test_output = [output]

testlock = threading.Lock()
class test(Task.Task):
    """Execute a test"""
    color = 'PINK'

    def keyword(self):
        return 'Running test'

    def runnable_status(self):
        if not self.generator.bld.cmd == 'test' and not getattr(self.generator, 'test_partofbuild', False):
            return Task.SKIP_ME
        ret = super(test, self).runnable_status()
        if ret == Task.SKIP_ME and getattr(self.generator, 'test_always', True):
            ret = Task.RUN_ME
        return ret

    def add_path(self, dct, path, var):
        dct[var] = os.pathsep.join(Utils.to_list(path) + [os.environ.get(var, '')])

    def get_test_env(self):
        """Add [[DY]LD_LIBRARY_]PATH to environment"""
        # this operation may be performed by at most #maxjobs
        fu = os.environ.copy()

        lst = []
        for g in self.generator.bld.groups:
            for tg in g:
                if getattr(tg, 'link_task', None):
                    s = tg.link_task.outputs[0].parent.abspath()
                    if s not in lst:
                        lst.append(s)

        if Utils.is_win32:
            self.add_path(fu, lst, 'PATH')
        elif Utils.unversioned_sys_platform() == 'darwin':
            self.add_path(fu, lst, 'DYLD_LIBRARY_PATH')
            self.add_path(fu, lst, 'LD_LIBRARY_PATH')
        else:
            self.add_path(fu, lst, 'LD_LIBRARY_PATH')

        return fu

    def run(self):
        self.last_cmd = [self.inputs[0].abspath()]
        cwd = self.inputs[0].parent.abspath()
        env = self.get_test_env()
        bld = self.generator.bld

        try:
            stdout, stderr = bld.cmd_and_log(self.last_cmd, env=env, cwd=cwd,
                    quiet=Context.BOTH, output=Context.BOTH)
            output = (self.last_cmd, None, stdout, stderr)
        except Errors.WafError as e:
            if not hasattr(e, 'returncode'):
                raise e
            output = (self.last_cmd, e.returncode, e.stdout, e.stderr)

        testlock.acquire()
        try:
            self.generator.add_test_output(output)
        finally:
            testlock.release()

        return output[1] if getattr(self.generator, 'test_mandatory', True) else None
