import base64
import json
import os
import signal
import subprocess
import time
import urllib.parse
import urllib.request

PROCESS = None
BASE_HEADERS = {"X-Rendezvous": base64.b64encode(os.urandom(20)).decode()}


def http_get(url):
    """
    Perform an HTTP GET request to the given URL.
    """
    return json.loads(urllib.request.urlopen(urllib.request.Request(url)).read().decode())


def http_post(url, headers=None, data=None):
    """
    Perform an HTTP POST request to the given URL.
    """
    if headers:
        headers.update(BASE_HEADERS)
    return json.loads(urllib.request.urlopen(urllib.request.Request(url, method="PUT", headers=headers, data=data))
                      .read().decode())


def urlstr(s):
    """
    Make the given string URL safe.
    """
    return urllib.parse.quote(s, safe='')


def wait_for_list(url, element=None):
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


def start():
    """
    Run the main.py script and wait for it to finish initializing.
    """
    global PROCESS
    PROCESS = subprocess.Popen('python3 main.py', shell=True, preexec_fn=os.setsid)
    os.waitpid(PROCESS.pid, os.P_NOWAITO)
    time.sleep(5.0)


def finish():
    """
    Kill our two IPv8 instances (running in the same process).
    """
    global PROCESS
    os.killpg(os.getpgid(PROCESS.pid), signal.SIGTERM)
    PROCESS.communicate()
