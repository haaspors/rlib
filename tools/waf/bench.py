#!/usr/bin/env python
#encoding: utf-8

"""test.py: Waf Test tools - inspired from waf_unit_test"""

__copyright__       = "Copyright 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>"
__license__         = "LGPL"
__author__          = "Haakon Sporsheim"
__email__           = "haakon.sporsheim@gmail.com"

import os
from waflib.Build import BuildContext
from waflib.TaskGen import feature, after_method
from waflib import Logs, Task, Options
from test import test, TestContext

class BenchContext(TestContext):
    '''extecutes benchmarks'''
    cmd = 'bench'

@feature('bench')
@after_method('apply_link')
def perform_benchmark(self):
    """Create the benchmark task."""
    if getattr(self, 'link_task', None):
        self.create_task('bench', self.link_task.outputs)

class bench(test):
    """Execute a benchmark test"""
    def keyword(self):
        if getattr(Options.options, 'valgrind', False) and self.generator.bld.env.VALGRIND:
            return 'Running benchmark under valgrind'
        else:
            return 'Running benchmark'

    def runnable_status(self):
        if not self.generator.bld.cmd == 'bench':
            return Task.SKIP_ME
        ret = super(test, self).runnable_status()
        return Task.RUN_ME if ret == Task.SKIP_ME else ret

