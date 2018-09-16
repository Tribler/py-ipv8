import inspect
import subprocess
import unittest
from os.path import abspath
from unittest.loader import TestLoader

from twisted.scripts.trial import _makeRunner, Options, _initialDebugSetup


class CustomSuite(unittest.TestSuite):

    def __init__(self, tests=()):
        stripped = []
        for test in tests:
            if isinstance(test, CustomSuite):
                stripped.append(test)
            elif any(member[0].startswith('test_') for member in inspect.getmembers(test)):
                stripped.append(test)
        super(CustomSuite, self).__init__(tests=stripped)


if __name__ == "__main__":
    # We have to regen the plugins cache to be able to install 
    # alternative reactors. Regen utility should be run in a separate
    # interpreter because reactors cannot be installed twice or unloaded.
    subprocess.call(["python", "regen_plugins_cache.py"])
    config = Options()
    config.parseOptions()
    config['tbformat'] = 'verbose'
    config['exitfirst'] = True

    _initialDebugSetup(config)
    trialRunner = _makeRunner(config)

    test_loader = TestLoader()
    test_loader.suiteClass = CustomSuite
    test_suite = test_loader.discover(abspath('./ipv8/test'),
                                      top_level_dir=abspath('.'))
    test_result = trialRunner.run(test_suite)
