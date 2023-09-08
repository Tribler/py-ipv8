import os
import sys
import time
from asyncio import Event, create_task, run, sleep
from os import chdir, getcwd, mkdir, path
from random import randint

# Check if we are running from the root directory
# If not, modify our path so that we can import IPv8
try:
    import ipv8
    del ipv8
except ImportError:
    import __scriptpath__  # noqa: F401

from ipv8.configuration import get_default_configuration  # noqa: I001
from ipv8.messaging.payload import IntroductionResponsePayload
from ipv8.messaging.payload_headers import GlobalTimeDistributionPayload
from ipv8.types import Community, Peer
from ipv8.util import create_event_with_signals

from ipv8_service import IPv8, _COMMUNITIES, _WALKERS


START_TIME = time.time()
RESULTS = {}


def custom_intro_response_cb(self: Community,
                             peer: Peer,
                             dist: GlobalTimeDistributionPayload,
                             payload: IntroductionResponsePayload,
                             event: Event) -> None:
    """
    Wait until we get a non-tracker response.
    Once all overlays have finished, stop the script.
    """
    if (peer.address not in self.network.blacklist) and (self.__class__.__name__ not in RESULTS):
        RESULTS[self.__class__.__name__] = time.time() - START_TIME
        print(self.__class__.__name__, "found a peer!", file=sys.stderr)  # noqa: T201
        if len(get_default_configuration()['overlays']) == len(RESULTS):
            event.set()


async def on_timeout(event: Event) -> None:
    """
    If it takes longer than 30 seconds to find anything, abort the experiment and set the intro time to -1.0.
    """
    await sleep(30)
    for definition in get_default_configuration()['overlays']:
        if definition['class'] not in RESULTS:
            RESULTS[definition['class']] = -1.0
            print(definition['class'], "found no peers at all!", file=sys.stderr)  # noqa: T201
    event.set()


async def start_communities() -> None:
    """
    Override the Community master peers so we don't interfere with the live network.
    Also hook in our custom logic for introduction responses.
    """
    event = create_event_with_signals()

    timeout_task = create_task(on_timeout(event))

    for community_cls in _COMMUNITIES.values():
        community_cls.community_id = os.urandom(20)
        community_cls.introduction_response_callback = lambda *args, e=event: custom_intro_response_cb(*args, e)

    # Create two peers with separate working directories
    instances = []
    previous_workdir = getcwd()
    for i in [1, 2]:
        configuration = get_default_configuration()
        configuration['port'] = 12000 + randint(0, 10000)
        configuration['logger']['level'] = "CRITICAL"
        for overlay in configuration['overlays']:
            overlay['walkers'] = [walker for walker in overlay['walkers'] if walker['strategy'] in _WALKERS]
        workdir = path.abspath(path.join(path.dirname(__file__), str(i)))
        if not path.exists(workdir):
            mkdir(workdir)
        chdir(workdir)
        ipv8 = IPv8(configuration)
        await ipv8.start()
        chdir(previous_workdir)
        instances.append(ipv8)

    await event.wait()
    timeout_task.cancel()

    for ipv8 in instances:
        await ipv8.stop()


# Actually start running everything, this blocks until the experiment finishes
run(start_communities())

# Print the introduction times for all default Communities, sorted alphabetically.
print(','.join(['%.4f' % RESULTS[key] for key in sorted(RESULTS)]))  # noqa: T201
