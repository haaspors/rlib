#!/usr/bin/env python
#encoding: utf-8

"""check.py: Waf ConfigurationContext tools"""

__copyright__       = "Copyright 2015 Haakon Sporsheim <haakon.sporsheim@gmail.com>"
__license__         = "MIT"
__author__          = "Haakon Sporsheim"
__email__           = "haakon.sporsheim@gmail.com"

from waflib.Configure import conf

@conf
def _compile_int(self, exp, **kw):
    headers = ['stdlib.h', 'stdio.h']
    if 'header_name' in kw:
        headers.append(kw['header_name'])
        del kw['header_name']
    kw['fragment'] = '''
            %s
            int main() { static int a[1-2*!(%s)]; a[0]=0; return 0; }
            ''' % (''.join(['#include <%s>\n' % x for x in headers]), exp);
    try:
        self.validate_c(kw)
        self.run_build(**kw)
        return True
    except Exception as e:
        return False

@conf
def compute_int(self, exp, l=-1, h=1024, **kw):
    if 'startmsg' not in kw:
        kw['startmsg'] = 'Checking for value of ' + e
    if 'errmsg' not in kw:
        kw['errmsg'] = 'Unknown'
    self.start_msg(kw['startmsg'])

    if 'guess' in kw:
        cur = kw['guess']
        if self._compile_int('%s == %d' % (exp, cur), **kw):
            self.end_msg(str(cur) + ' (guessed)');
            return cur

    while l < h:
        cur = int((l+h) / 2)
        if cur == l:
            break;

        if self._compile_int('%s >= %d' % (exp, cur), **kw):
            l = cur
        else:
            h = cur

    if self._compile_int('%s == %d' % (exp, cur), **kw):
        self.end_msg(str(cur));
        return cur
    else:
        self.end_msg(kw['errmsg'], 'YELLOW');
        return None

@conf
def check_sizeof(self, t, l=1, h=17, **kw):
    kw['startmsg'] = 'Checking for sizeof ' + t
    return self.compute_int('(long int) sizeof(%s)' % t, l, h, **kw)
