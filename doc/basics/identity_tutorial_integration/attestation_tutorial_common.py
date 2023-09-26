from __future__ import annotations

import base64
import json
import os
import signal
import subprocess
import time
import urllib.parse
import urllib.request
from typing import Any, cast

PROCESS = None
BASE_HEADERS = {"X-Rendezvous": base64.b64encode(os.urandom(20)).decode()}


def http_get(url: str) -> Any:
    """
    Perform an HTTP GET request to the given URL.
    """
    return json.loads(urllib.request.urlopen(urllib.request.Request(url)).read().decode())  # noqa: S310


def http_post(url: str, headers: dict[str, str] | None = None, data: bytes | None = None) -> Any:
    """
    Perform an HTTP POST request to the given URL.
    """
    if headers:
        headers.update(BASE_HEADERS)
    return json.loads(urllib.request.urlopen(urllib.request.Request(url,  # noqa: S310
                                                                    method="PUT", headers=headers, data=data))
                      .read().decode())


def urlstr(s: str) -> str:
    """
    Make the given string URL safe.
    """
    return urllib.parse.quote(s, safe='')


def wait_for_list(url: str, element: str | None = None) -> list:
    """
    Poll an endpoint until output (a list) is available.
    """
    out = []
    while not out:
        out = http_get(url)
        if element:
            out = out[element]
        time.sleep(0.5)
    return out


def start() -> None:
    """
    Run the main.py script and wait for it to finish initializing.
    """
    global PROCESS  # noqa: PLW0603
    PROCESS = subprocess.Popen('python3 main.py', shell=True, preexec_fn=os.setsid)  # noqa: PLW1509,S602,S607
    os.waitpid(PROCESS.pid, os.P_NOWAITO)
    time.sleep(5.0)


def finish() -> None:
    """
    Kill our two IPv8 instances (running in the same process).
    """
    process = cast(subprocess.Popen, PROCESS)
    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    process.communicate()
