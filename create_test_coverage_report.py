import logging
import os
import shutil
import sys
from io import StringIO
from unittest import TextTestRunner, defaultTestLoader
from unittest.suite import TestSuite

import coverage

if __name__ != '__main__':
    print(__file__, "should be run stand-alone! Instead, it is being imported!", file=sys.stderr)
    sys.exit(1)

data_file = os.path.join('coverage', 'raw', 'coverage_file')
logging.basicConfig(level=logging.CRITICAL)
logging.disable(logging.CRITICAL)


def clean_directory(prepare=False):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'coverage', 'raw')
    if os.path.isdir(path):
        shutil.rmtree(path)
    if prepare:
        os.makedirs(path)


clean_directory(prepare=True)

with open('test_classes_list.txt', 'r') as test_class_file:
    lines = [line[:-1] for line in test_class_file.readlines() if line.strip() and not line.startswith('#')]

    cov = coverage.Coverage(data_file=data_file, data_suffix=True, config_file=False,
                            branch=True, source=['ipv8'], include=['*'], omit=["ipv8/test/*", "ipv8_service.py"])
    cov.exclude('pass')
    cov.start()

    for line in lines:
        print("Measuring coverage for", line)

        output_stream = StringIO()
        formatted_line = line.replace('/', '.').replace('.py:', '.')

        suite = TestSuite()
        suite.addTest(defaultTestLoader.loadTestsFromName(formatted_line))
        reporter = TextTestRunner(stream=output_stream, failfast=True)
        test_result = reporter.run(suite)

        assert len(test_result.errors) == 0,\
            "ERROR: UNIT TESTS FAILED, PLEASE FIX BEFORE RUNNING COVERAGE:\n%s\n%s" % (output_stream.getvalue(), ''.join([repr(error) for error in test_result.errors]))
        output_stream.close()

    cov.stop()
    print("Generating HTML report")
    cov.html_report(directory='coverage', omit="ipv8/keyvault/libnacl/*")
    cov.erase()

clean_directory()
