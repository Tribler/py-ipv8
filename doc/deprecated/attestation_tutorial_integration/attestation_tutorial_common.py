import binascii
import json
import os
import signal
import subprocess
import time
import urllib.parse
import urllib.request
from typing import Any, cast

PROCESS = None
ID1 = binascii.hexlify(os.urandom(20)).decode()
ID2 = binascii.hexlify(os.urandom(20)).decode()
ID3 = binascii.hexlify(os.urandom(20)).decode()


def http_get(url: str) -> Any:
    """
    Perform an HTTP GET request to the given URL.
    """
    return json.loads(urllib.request.urlopen(urllib.request.Request(url)).read().decode())  # noqa: S310


def http_post(url: str) -> Any:
    """
    Perform an HTTP POST request to the given URL.
    """
    return json.loads(urllib.request.urlopen(urllib.request.Request(url, method="POST")).read().decode())  # noqa: S310


def urlstr(s: str) -> str:
    """
    Make the given string URL safe.
    """
    return urllib.parse.quote(s, safe='')


def wait_for_list(url: str) -> list:
    """
    Poll an endpoint until output (a list) is available.
    """
    out = []
    while not out:
        out = http_get(url)
        time.sleep(0.5)
    return out


def start() -> None:
    """
    Run the main.py script and wait for it to finish initializing.
    """
    global PROCESS  # noqa: PLW0603
    PROCESS = subprocess.Popen(f'python3 main.py {ID1} {ID2} {ID3}',
                               shell=True, preexec_fn=os.setsid)  # noqa: PLW1509,S602
    os.waitpid(PROCESS.pid, os.P_NOWAITO)
    time.sleep(5.0)


def finish() -> None:
    """
    Kill our two IPv8 instances (running in the same process).
    """
    process = cast(subprocess.Popen, PROCESS)
    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    process.communicate()
