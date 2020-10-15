from asyncio import ensure_future, get_event_loop
from base64 import b64encode

from pyipv8.ipv8.REST.rest_manager import RESTManager
from pyipv8.ipv8.configuration import get_default_configuration
from pyipv8.ipv8_service import IPv8


async def start_communities():
    # Launch two IPv8 services.
    # We run REST endpoints for these services on:
    #  - http://localhost:14411/
    #  - http://localhost:14412/
    # This script also prints the peer ids for reference with:
    #  - http://localhost:1441*/attestation?type=peers
    for i in [1, 2]:
        configuration = get_default_configuration()
        configuration['logger']['level'] = "ERROR"
        configuration['keys'] = [
            {'alias': "anonymous id", 'generation': u"curve25519", 'file': u"ec%d_multichain.pem" % i},
        ]

        # Only load the basic communities
        requested_overlays = ['DiscoveryCommunity', 'AttestationCommunity', 'IdentityCommunity']
        configuration['overlays'] = [o for o in configuration['overlays'] if o['class'] in requested_overlays]

        # Give each peer a separate working directory
        working_directory_overlays = ['AttestationCommunity', 'IdentityCommunity']
        for overlay in configuration['overlays']:
            if overlay['class'] in working_directory_overlays:
                overlay['initialize'] = {'working_directory': 'state_%d' % i}

        # Start the IPv8 service
        ipv8 = IPv8(configuration)
        await ipv8.start()
        rest_manager = RESTManager(ipv8)
        await rest_manager.start(14410 + i)

        # Print the peer for reference
        print("Starting peer", b64encode(ipv8.keys["anonymous id"].mid))


ensure_future(start_communities())
get_event_loop().run_forever()
