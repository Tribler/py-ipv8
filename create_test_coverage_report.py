import logging
import os
import pathlib
import platform
import shutil
import sys
from io import StringIO
from unittest import TextTestRunner, defaultTestLoader
from unittest.suite import TestSuite

import coverage
from coverage.files import abs_file, relative_filename
from coverage.python import PythonFileReporter
from coverage.results import Analysis
from packaging.version import Version

from run_all_tests import find_all_test_class_names, install_libsodium, windows_missing_libsodium

if __name__ != '__main__':
    print(__file__, "should be run stand-alone! Instead, it is being imported!", file=sys.stderr)  # noqa: T201
    sys.exit(1)

if platform.system() == 'Windows' and windows_missing_libsodium():
    print("Failed to locate libsodium (libnacl requirement), downloading latest dll!")  # noqa: T201
    install_libsodium()

data_file = os.path.join('coverage', 'raw', 'coverage_file')
logging.basicConfig(level=logging.CRITICAL)
logging.disable(logging.CRITICAL)


def clean_directory(prepare: bool = False) -> None:
    """
    Remove all files in the ``coverage/raw`` directory.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'coverage', 'raw')
    if os.path.isdir(path):
        shutil.rmtree(path)
    if prepare:
        os.makedirs(path)


clean_directory(prepare=True)

test_paths = find_all_test_class_names()

# The find_all_test_class_names method imports and scans all source files.
# This causes the coverage module to not consider module-level imports covered.
# We remove them again to get the correct coverage.
# We also remove the singleton entries for the REST API to avoid double binding to names.
for module_name in list(sys.modules.keys()):
    if module_name.startswith(('ipv8', 'marshmallow', 'apispec', 'aiohttp')):
        del sys.modules[module_name]

cov = coverage.Coverage(data_file=data_file, data_suffix=True, config_file=False,
                        branch=True, source=['ipv8'], include=['*'], omit=["ipv8/test/*", "ipv8_service.py"])
cov.exclude('pass')
cov.start()

for test_path in test_paths:
    print("Measuring coverage for", test_path)  # noqa: T201

    output_stream = StringIO()

    suite = TestSuite()
    suite.addTest(defaultTestLoader.loadTestsFromName(test_path))
    reporter = TextTestRunner(stream=output_stream, failfast=True)
    test_result = reporter.run(suite)

    error_string = ''.join([repr(error) for error in test_result.errors])
    assert len(test_result.errors) == 0,\
        f"ERROR: UNIT TESTS FAILED, PLEASE FIX BEFORE RUNNING COVERAGE:\n{output_stream.getvalue()}\n{error_string}"
    output_stream.close()

cov.stop()
print("Generating HTML report")  # noqa: T201
cov.html_report(directory='coverage')

print("Generating markdown report")  # noqa: T201
with open('coverage.md', 'w') as fp:
   cov.report(output_format='markdown', file=fp, show_missing=True)

print("Aggregating package stats")  # noqa: T201
total_numbers = {}  # Package name -> (Numbers: package coverage stats, dict: files per coverage bin)
for filename in cov.get_data().measured_files():
    file_reporter = PythonFileReporter(filename, cov)
    if Version(coverage.__version__) < Version("5"):
        analysis = Analysis(cov.get_data(), file_reporter)
    elif Version(coverage.__version__) < Version("6"):
        analysis = Analysis(cov.get_data(), file_reporter, abs_file)
    elif Version(coverage.__version__) < Version("7.5"):
        analysis = Analysis(cov.get_data(), 0, file_reporter, abs_file)
    else:
        from coverage.results import analysis_from_file_reporter
        analysis = analysis_from_file_reporter(cov.get_data(), 0, file_reporter, abs_file)

    # If the package name does not contain more than 2 parts, it's a top-level file.
    package_path = pathlib.Path(relative_filename(filename))
    package = ".".join(package_path.parts[:2 if len(package_path.parts) > 2 else 1])
    package_stats = total_numbers.get(package)

    # Put all exactly 100% coverage files into the 80%-100% bin
    individual_coverage = min(4, int(analysis.numbers.pc_covered / 20.0))

    if not package_stats:
        total_numbers[package] = (analysis.numbers, {individual_coverage: 1})
    else:
        package_numbers, package_buckets = package_stats
        package_buckets[individual_coverage] = 1 + package_buckets.get(individual_coverage, 0)
        total_numbers[package] = (package_numbers + analysis.numbers, package_buckets)

print("Generating R barplot script")  # noqa: T201
with open(os.path.join('coverage', 'plotbars.R'), 'w') as barplot_script:
    package_count = len(total_numbers)
    barplot_script.write(f"""
png(filename = "coverage_barplot.png", width = 500, height = {150 * package_count})
par(mfrow=c({package_count},1))\n""")
    for package_name, stats in total_numbers.items():
        numbers, buckets = stats
        barplot_script.write(f"""
barplot(c({",".join([str(buckets.get(k, 0)) for k in range(5)])}),
    names.arg=c("0-19", "20-39", "40-59", "60-79", "80-100"),
    main="{package_name} (total coverage: {round(numbers.pc_covered, 2)!s})")\n""")
    barplot_script.write("\ndev.off()\n")

print("Cleaning up..")  # noqa: T201
cov.erase()
clean_directory()
