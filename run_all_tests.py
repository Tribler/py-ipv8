import argparse
import importlib
import inspect
import io
import multiprocessing
import pathlib
import sys
import threading
import time
import unittest


def programmer_distractor():
    distraction = str(int(time.time() - programmer_distractor.starttime))
    print('\033[u\033[K' + distraction + " seconds and counting "
          + ("x" if int(time.time() * 10) % 2 else "+"), end="", flush=True)
    programmer_distractor.t = threading.Timer(0.1, programmer_distractor)
    programmer_distractor.t.start()


class CustomTestResult(unittest.TextTestResult):

    def __init__(self, stream, descriptions, verbosity):
        super(CustomTestResult, self).__init__(stream, descriptions, verbosity)
        self.start_time = 0
        self.end_time = 0
        self.last_test = 0

    def getDescription(self, test):
        return str(test)

    def startTestRun(self) -> None:
        super(CustomTestResult, self).startTestRun()
        self.start_time = time.time()
        self.end_time = self.start_time

    def startTest(self, test: unittest.case.TestCase) -> None:
        super(CustomTestResult, self).startTest(test)
        self.last_test = time.time()

    def addSuccess(self, test):
        super(unittest.TextTestResult, self).addSuccess(test)
        if self.showAll:
            self.stream.writeln(f"ok [{round((time.time() - self.last_test) * 1000, 2)} ms]")
        elif self.dots:
            self.stream.write('.')
            self.stream.flush()

    def stopTestRun(self) -> None:
        super(CustomTestResult, self).stopTestRun()
        self.end_time = time.time()


class CustomLinePrint(io.StringIO):

    def __init__(self, delegated, prefix):
        super(CustomLinePrint, self).__init__()
        self.prefix = prefix
        self.delegated = delegated
        self.raw_lines = []

    def write(self, __text: str) -> int:
        wtime = time.time()
        self.raw_lines.append((wtime, self.prefix, __text))
        return self.delegated.write(__text)


def task_test(*test_names):
    import logging

    print_stream = io.StringIO()
    output_stream = CustomLinePrint(print_stream, "OUT")
    stdio_replacement = CustomLinePrint(print_stream, "OUT")
    stderr_replacement = CustomLinePrint(print_stream, "ERR")
    logging_replacement = CustomLinePrint(print_stream, "LOG")
    sys.stdio = stdio_replacement
    sys.stderr = stderr_replacement
    logging.basicConfig(level="DEBUG", stream=logging_replacement,
                        format="%(levelname)-7s %(created).2f %(module)18s:%(lineno)-4d (%(name)s)  %(message)s")

    suite = unittest.TestSuite()
    for test_name in test_names:
        suite.addTest(unittest.defaultTestLoader.loadTestsFromName(test_name))
    reporter = unittest.TextTestRunner(stream=output_stream, failfast=True, verbosity=2, resultclass=CustomTestResult)
    test_result = reporter.run(suite)

    failed = len(test_result.errors) > 0 or len(test_result.failures) > 0
    event_log = []
    event_log.extend(output_stream.raw_lines if failed else output_stream.raw_lines[:-9])
    event_log.extend(stdio_replacement.raw_lines)
    event_log.extend(stderr_replacement.raw_lines)
    if failed and logging_replacement.raw_lines:
        relevant_log = [line for line in logging_replacement.raw_lines if line[0] >= test_result.last_test]
        event_log.append((relevant_log[0][0], "LOG", "\n"))
        event_log.extend(relevant_log)

    return (failed, test_result.testsRun, test_result.end_time - test_result.start_time,
            event_log, print_stream.getvalue())


def scan_for_test_files(directory=pathlib.Path('./ipv8/test')):
    if not isinstance(directory, pathlib.Path):
        directory = pathlib.Path(directory)
    return directory.glob('**/test_*.py')


def derive_test_class_names(test_file_path):
    module_name = '.'.join(test_file_path.relative_to(pathlib.Path('.')).parts)[:-3]
    module_instance = importlib.import_module(module_name)
    test_class_names = []
    for obj_name, obj in inspect.getmembers(module_instance):
        if inspect.isclass(obj) and issubclass(obj, unittest.TestCase) and obj.__module__ == module_name:
            test_class_names.append(f"{module_name}.{obj_name}")
    return test_class_names


def find_all_test_class_names(directory=pathlib.Path('./ipv8/test')):
    if not isinstance(directory, pathlib.Path):
        directory = pathlib.Path(directory)
    test_class_names = []
    for found_test in scan_for_test_files(directory):
        test_class_names.extend(derive_test_class_names(found_test))
    return test_class_names


def make_buckets(path_list, groups):
    bucket_size = len(path_list) // groups
    bucket_rem = len(path_list) - bucket_size * groups
    buckets = []
    for i in range(groups):
        buckets.append(tuple(path_list[(i * bucket_size + min(i, bucket_rem)):
                                       ((i + 1) * bucket_size) + min(i + 1, bucket_rem)]))
    return buckets


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run the IPv8 tests.')
    parser.add_argument('-p', '--processes', type=int, default=multiprocessing.cpu_count() * 2, required=False,
                        help="The amount of processes to spawn.")
    parser.add_argument('-q', '--quiet', action='store_true', required=False,
                        help="Don't show succeeded tests.")
    args = parser.parse_args()

    process_count = args.processes
    process_pool = multiprocessing.Pool(process_count)

    test_class_names = find_all_test_class_names()
    buckets = make_buckets(test_class_names, process_count)

    print(f"Launching in {process_count} processes ... ", end="")
    total_end_time = 0
    total_start_time = time.time()
    result = process_pool.starmap_async(task_test, buckets)
    print(f"awaiting results ... \033[s", end="", flush=True)

    programmer_distractor.starttime = time.time()
    timer = threading.Timer(0.1, programmer_distractor)
    programmer_distractor.t = timer
    timer.start()

    global_event_log = []
    total_time_taken = 0
    total_tests_run = 0
    total_fail = False
    print_output = ''

    for process_output_handle in result.get():
        if total_end_time == 0:
            total_end_time = time.time()
        failed, tests_run, time_taken, event_log, print_output = process_output_handle
        total_fail |= failed
        total_tests_run += tests_run
        total_time_taken += time_taken
        if failed:
            global_event_log = event_log
            break
        global_event_log.extend(event_log)

    process_pool.close()
    process_pool.join()
    programmer_distractor.t.cancel()

    print(f"\033[u\033[Kdone!", end="\r\n\r\n", flush=True)

    if total_fail or not args.quiet:
        print(unittest.TextTestResult.separator1)
        global_event_log.sort(key=lambda x: x[0])
        for event in global_event_log:
            print(('\033[91m' if event[1] == "ERR" else ('\033[94m' if event[1] == "LOG" else '\033[0m'))
                  + event[2] + '\033[0m',
                  end='')
        print("\r\n" + unittest.TextTestResult.separator1)

    print("Summary:")
    if total_fail:
        print("[\033[91mFAILED\033[0m", end="")
    else:
        print("[\033[32mSUCCESS\033[0m", end="")
    print(f"] Ran {total_tests_run} tests "
          f"in {round(total_end_time-total_start_time, 2)} seconds "
          f"({round(total_time_taken, 2)} seconds total in tests).")

    if total_fail:
        sys.exit(1)
