from __future__ import absolute_import
from __future__ import division

import sys

from twisted.internet import reactor


if __name__ == '__main__':
    from twisted.plugins.ipv8_plugin import Options, service_maker

    options = Options()
    Options.parseOptions(options, sys.argv[1:])
    service_maker.makeService(options)
    reactor.run()
