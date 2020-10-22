import binascii
import json
import os
import signal
import subprocess
import time
import urllib.parse
import urllib.request

PROCESS = None
ID1 = binascii.hexlify(os.urandom(20)).decode()
ID2 = binascii.hexlify(os.urandom(20)).decode()
ID3 = binascii.hexlify(os.urandom(20)).decode()


def http_get(url):
    """
    Perform an HTTP GET request to the given URL.
    """
    return json.loads(urllib.request.urlopen(urllib.request.Request(url)).read().decode())


def http_post(url):
    """
    Perform an HTTP POST request to the given URL.
    """
    return json.loads(urllib.request.urlopen(urllib.request.Request(url, method="POST")).read().decode())


def urlstr(s):
    """
    Make the given string URL safe.
    """
    return urllib.parse.quote(s, safe='')


def wait_for_list(url):
    """
    Poll an endpoint until output (a list) is available.
    """
    out = []
    while not out:
        out = http_get(url)
        time.sleep(0.5)
    return out


def start():
    """
    Run the main.py script and wait for it to finish initializing.
    """
    global PROCESS
    PROCESS = subprocess.Popen(f'python3 main.py {ID1} {ID2} {ID3}', shell=True, preexec_fn=os.setsid)
    os.waitpid(PROCESS.pid, os.P_NOWAITO)
    time.sleep(5.0)


def finish():
    """
    Kill our two IPv8 instances (running in the same process).
    """
    global PROCESS
    os.killpg(os.getpgid(PROCESS.pid), signal.SIGTERM)
    PROCESS.communicate()
