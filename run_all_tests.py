import inspect
import unittest
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
    config = Options()
    config.parseOptions()
    config['tbformat'] = 'verbose'
    config['exitfirst'] = True


    # TODO: write our own parallel testing module for Trial on Windows
    # Workaround for Trial not supporting parallel testing on Windows
    #if platformType == "posix":
    #    import multiprocessing
    #    config.opt_jobs(multiprocessing.cpu_count())

    _initialDebugSetup(config)
    trialRunner = _makeRunner(config)

    test_loader = TestLoader()
    test_loader.suiteClass = CustomSuite
    test_suite = test_loader.discover('./ipv8/test', top_level_dir='.')
    test_result = trialRunner.run(test_suite)
