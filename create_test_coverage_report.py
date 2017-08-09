import sys

if __name__ != '__main__':
    print >> sys.stderr, __file__, "should be run stand-alone! Instead, it is being imported!"
    sys.exit(1)

import logging
logging.basicConfig(level=logging.CRITICAL)
logging.disable(logging.CRITICAL)

import coverage
import os
import shutil
from StringIO import StringIO
import unittest

data_file = os.path.join('coverage', 'raw', 'coverage_file')

def clean_directory(prepare=False):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'coverage', 'raw')
    if os.path.isdir(path):
        shutil.rmtree(path)
    if prepare:
        os.makedirs(path)

clean_directory(prepare=True)

with open('test_classes_list.txt', 'r') as test_class_file:
    lines = [line[:-1] for line in test_class_file.readlines() if line.strip() and not line.startswith('#')]
    cov = None
    for line in lines:
        if cov:
            cov.stop()
            cov.save()
            del cov
        print "Measuring coverage for", line
        cov = coverage.Coverage(data_file=data_file, data_suffix=True, config_file=False,
                                branch=True, source=['ipv8'], include=['*'], omit="ipv8/ipv8.py")
        cov.load()
        cov.exclude('pass')
        cov.start()

        output_stream = StringIO()
        formatted_line = line.replace('/', '.').replace('.py:', '.')
        suite = unittest.TestLoader().loadTestsFromName(formatted_line)
        unittest.TextTestRunner(failfast=True, stream=output_stream, verbosity=0).run(suite)
        assert "\nOK\n" in output_stream.getvalue(), "ERROR: UNIT TESTS FAILED, PLEASE FIX BEFORE RUNNING COVERAGE"
        output_stream.close()

    if cov:
        cov.combine()
        print "Generating HTML report"
        cov.html_report(directory='coverage', omit="ipv8/keyvault/libnacl/*")
        cov.stop()

clean_directory()
