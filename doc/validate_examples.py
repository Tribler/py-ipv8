"""
This script runs through all of the .py files in the subfolders of the ``/doc`` folder and runs them.
If any of the scripts has tracebacks during their execution, this file exits with status 1.
"""
import multiprocessing
import os
import sys
import threading


TOP_DIRECTORY = os.path.dirname(os.path.dirname(os.path.realpath('__file__')))


def validate_run(stdout: multiprocessing.Pipe, stderr: multiprocessing.Pipe, module_path: str):
    """
    Run the example from ``module_path`` isolated in a process.

    This fakes the subfolder execution of the example scripts by loading them into the TOP_DIRECTORY path and
    replaces all of the ``from pyipv8`` imports in the example scripts.
    """
    os.dup2(stdout.fileno(), 1)  # Forward all stdout (1) calls to the stdout argument
    os.dup2(stderr.fileno(), 2)  # Forward all stderr (2) calls to the stdout argument

    sys.path.insert(0, TOP_DIRECTORY)

    with open(module_path, 'r') as module_file_h:
        module_contents = ""
        line = module_file_h.readline()
        while line:
            if line.startswith("from pyipv8."):
                line = "from " + line[len("from pyipv8."):]
            module_contents += line
            line = module_file_h.readline()

    exec(compile(module_contents, module_path, 'exec', dont_inherit=True, optimize=0), {})  # pylint: disable=W0122


def safe_close(stream):
    """
    Always works, even if stream is already closed.
    """
    try:
        stream.close()
    except OSError:
        pass


def empty_reader(input_buffer, output_list: list):
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
                absfile_path = os.path.abspath(os.path.join(TOP_DIRECTORY, "doc", path, subfile))

                # Open the stderr and stdio redirection Pipes.
                r_stdout, w_stdout = multiprocessing.Pipe()
                reader_stdout = os.fdopen(r_stdout.fileno(), 'r')
                output_stdout = []

                r_stderr, w_stderr = multiprocessing.Pipe()
                reader_stderr = os.fdopen(r_stderr.fileno(), 'r')
                output_stderr = []

                # Run in isolation, so scripts don't inherit each others mess.
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
