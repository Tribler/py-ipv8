"""
This script runs through all the .py files in the subfolders of the ``/doc`` folder and runs them.
If any of the scripts has tracebacks during their execution, this file exits with status 1.
"""
from __future__ import annotations

import contextlib
import importlib.util
import multiprocessing
import os
import sys
import threading
from multiprocessing import connection
from typing import TextIO

TOP_DIRECTORY = os.path.dirname(os.path.dirname(os.path.realpath('__file__')))


def validate_run(stdout: multiprocessing.Pipe, stderr: multiprocessing.Pipe, module_path: str) -> None:
    """
    Run the example from ``module_path`` isolated in a process.
    """
    os.dup2(stdout.fileno(), 1)  # Forward all stdout (1) calls to the stdout argument
    os.dup2(stderr.fileno(), 2)  # Forward all stderr (2) calls to the stdout argument

    sys.path.insert(0, TOP_DIRECTORY)

    actual_main = sys.modules["__main__"]

    # We swap out the "__main__" module (this file) to the given file.
    # This is slightly dangerous because the loaded "__main__" module now contains objects that are not in the
    # currently loaded "__main__" module. In most cases, this is not an issue as (1) no introspection is done on the
    # "__main__" module and (2) overwriting previously set names does not cause issues.
    spec = importlib.util.spec_from_file_location("__main__", module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["__main__"] = module
    spec.loader.exec_module(module)

    sys.modules["__main__"] = actual_main


def safe_close(stream: connection.Connection | TextIO) -> None:
    """
    Always works, even if stream is already closed.
    """
    with contextlib.suppress(OSError):
        stream.close()


def empty_reader(input_buffer: TextIO, output_list: list) -> None:
    """
    Consume lines from the ``input_buffer`` and append to the ``output_list``.

    Deals with all sorts of stream breaking while reading.
    """
    while input_buffer.readable():
        try:
            output_list.append(input_buffer.readline())
        except (OSError, ValueError):
            break
    safe_close(input_buffer)


success = True
for path in os.listdir("."):
    if os.path.isdir(path):
        for subfile in os.listdir(path):
            if subfile.endswith(".py"):
                absfile_path = os.path.join(path, subfile)

                # Open the stderr and stdio redirection Pipes.
                r_stdout, w_stdout = multiprocessing.Pipe()
                reader_stdout = os.fdopen(r_stdout.fileno(), 'r')
                output_stdout = []

                r_stderr, w_stderr = multiprocessing.Pipe()
                reader_stderr = os.fdopen(r_stderr.fileno(), 'r')
                output_stderr = []

                # Run in isolation, so scripts don't inherit each other's mess.
                p = multiprocessing.Process(target=validate_run, args=(w_stdout, w_stderr, absfile_path))
                p.start()

                # You can't read from a closed Pipe (conveniently, this blocks forever). So, we need threads.
                t_stdout = threading.Thread(target=empty_reader, daemon=True, args=(reader_stdout, output_stdout))
                t_stdout.start()
                t_stderr = threading.Thread(target=empty_reader, daemon=True, args=(reader_stderr, output_stderr))
                t_stderr.start()

                p.join(30.0)
                if p.is_alive():
                    print(f"Killed {subfile} after 30 seconds!")
                    p.kill()

                captured_stdout = "".join(output_stdout)
                captured_stderr = "".join(output_stderr)

                # Close everything, note that some processes may be crashed/terminated or deadlocked.
                safe_close(r_stdout)
                safe_close(w_stdout)
                safe_close(r_stderr)
                safe_close(w_stderr)
                safe_close(reader_stdout)
                safe_close(reader_stderr)

                # Finally, check if the word "Traceback" occurs in any output.
                if "Traceback" in captured_stdout or "Traceback" in captured_stderr:
                    print(f"[FAILED] Traceback detected in {subfile}")
                    print("=== stdout ===")
                    print(captured_stdout)
                    print("=== stderr ===")
                    print(captured_stderr)
                    success = False
                else:
                    print(f"[SUCCESS] No tracebacks detected in {subfile}")

sys.exit(0 if success else 1)
