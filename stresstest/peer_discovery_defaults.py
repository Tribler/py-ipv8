import sys
import time
from asyncio import ensure_future, get_event_loop, sleep
from os import chdir, getcwd, mkdir, path
from random import randint

# Check if we are running from the root directory
# If not, modify our path so that we can import IPv8
try:
    import ipv8
    del ipv8
except ImportError:
    import __scriptpath__  # noqa: F401


from ipv8.configuration import get_default_configuration  # pylint: disable=ungrouped-imports
from ipv8.keyvault.crypto import ECCrypto  # pylint: disable=ungrouped-imports
from ipv8.peer import Peer  # pylint: disable=ungrouped-imports

from ipv8_service import IPv8, _COMMUNITIES, _WALKERS  # pylint: disable=ungrouped-imports


START_TIME = time.time()
RESULTS = {}


# Wait until we get a non-tracker response
# Once all overlays have finished, stop the script
def custom_intro_response_cb(self, peer, dist, payload):
    if (peer.address not in self.network.blacklist) and (self.__class__.__name__ not in RESULTS):
        RESULTS[self.__class__.__name__] = time.time() - START_TIME
        print(self.__class__.__name__, "found a peer!", file=sys.stderr)
        if len(get_default_configuration()['overlays']) == len(RESULTS):
            get_event_loop().stop()


# If it takes longer than 30 seconds to find anything, abort the experiment and set the intro time to -1.0
async def on_timeout():
    await sleep(30)
    for definition in get_default_configuration()['overlays']:
        if definition['class'] not in RESULTS:
            RESULTS[definition['class']] = -1.0
            print(definition['class'], "found no peers at all!", file=sys.stderr)
    get_event_loop().stop()


async def start_communities():
    # Override the Community master peers so we don't interfere with the live network
    # Also hook in our custom logic for introduction responses
    for community_cls in _COMMUNITIES.values():
        community_cls.master_peer = Peer(ECCrypto().generate_key(u"medium"))
        community_cls.introduction_response_callback = custom_intro_response_cb

    # Create two peers with separate working directories
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
        await IPv8(configuration).start()
        chdir(previous_workdir)

# Actually start running everything, this blocks until the experiment finishes
ensure_future(on_timeout())
ensure_future(start_communities())
get_event_loop().run_forever()

# Print the introduction times for all default Communities, sorted alphabetically.
print(','.join(['%.4f' % RESULTS[key] for key in sorted(RESULTS)]))
