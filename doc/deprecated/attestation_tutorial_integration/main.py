from asyncio import ensure_future, get_event_loop
from base64 import b64encode
from binascii import unhexlify
from sys import argv

from ipv8.REST.rest_manager import RESTManager
from ipv8.attestation.identity.community import IdentityCommunity
from ipv8.attestation.wallet.community import AttestationCommunity
from ipv8.configuration import DISPERSY_BOOTSTRAPPER, get_default_configuration
from ipv8.peerdiscovery.community import DiscoveryCommunity

from ipv8_service import IPv8


class IsolatedIdentityCommunity(IdentityCommunity):
    community_id = unhexlify(argv[1])


class IsolatedAttestationCommunity(AttestationCommunity):
    community_id = unhexlify(argv[2])


class IsolatedDiscoveryCommunity(DiscoveryCommunity):
    community_id = unhexlify(argv[3])


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
            {'alias': "anonymous id", 'generation': u"curve25519", 'file': u"ec%d_multichain.pem" % i}
        ]

        # Only load the basic communities
        configuration['overlays'] = [{
            'class': 'IsolatedDiscoveryCommunity',
            'key': "anonymous id",
            'walkers': [
                {
                    'strategy': "RandomWalk",
                    'peers': 20,
                    'init': {
                        'timeout': 3.0
                    }
                },
                {
                    'strategy': "RandomChurn",
                    'peers': -1,
                    'init': {
                        'sample_size': 8,
                        'ping_interval': 10.0,
                        'inactive_time': 27.5,
                        'drop_time': 57.5
                    }
                },
                {
                    'strategy': "PeriodicSimilarity",
                    'peers': -1,
                    'init': {}
                }
            ],
            'bootstrappers': [DISPERSY_BOOTSTRAPPER],
            'initialize': {},
            'on_start': []
        },
            {
                'class': 'IsolatedAttestationCommunity',
                'key': "anonymous id",
                'walkers': [{
                    'strategy': "RandomWalk",
                    'peers': 20,
                    'init': {
                        'timeout': 3.0
                    }
                }],
                'bootstrappers': [DISPERSY_BOOTSTRAPPER],
                'initialize': {'working_directory': 'state_%d' % i},
                'on_start': []
            },
            {
                'class': 'IsolatedIdentityCommunity',
                'key': "anonymous id",
                'walkers': [{
                    'strategy': "RandomWalk",
                    'peers': 20,
                    'init': {
                        'timeout': 3.0
                    }
                }],
                'bootstrappers': [DISPERSY_BOOTSTRAPPER],
                'initialize': {'working_directory': 'state_%d' % i},
                'on_start': []
            }]

        # Start the IPv8 service
        ipv8 = IPv8(configuration, extra_communities={
            'IsolatedDiscoveryCommunity': IsolatedDiscoveryCommunity,
            'IsolatedAttestationCommunity': IsolatedAttestationCommunity,
            'IsolatedIdentityCommunity': IsolatedIdentityCommunity
        })
        await ipv8.start()
        rest_manager = RESTManager(ipv8)
        await rest_manager.start(14410 + i)

        # Print the peer for reference
        print("Starting peer", b64encode(ipv8.keys["anonymous id"].mid))


ensure_future(start_communities())
get_event_loop().run_forever()
