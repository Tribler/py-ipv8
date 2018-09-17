from __future__ import absolute_import

import re
import sys
from nose import run_exit

if __name__ == '__main__':
    # We try to use the reactor that does not use 'select' or '*poll' to
    # avoid hitting Twisted bug that causes the reactor to wait on
    # cancelled delayed calls when all delayed calls are cancelled.
    try:
        from twisted.internet import glib2reactor as reactor
    except ImportError:
        from twisted.internet import selectreactor as reactor

    reactor.install()

    # Shameless copypaste from nosetests.py, for complete compatibility
    # of command line arguments
    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    sys.exit(run_exit())
