from asyncio import run
from base64 import b64encode
from time import sleep

from ipv8.configuration import get_default_configuration
from ipv8.REST.rest_manager import RESTManager
from ipv8.util import run_forever
from ipv8_service import IPv8


async def start_community() -> None:
    for peer_id in [1, 2]:
        configuration = get_default_configuration()
        configuration['logger']['level'] = "ERROR"
        configuration['keys'] = [{'alias': "anonymous id",
                                  'generation': "curve25519",
                                  'file': f"keyfile_{peer_id}.pem"}]
        configuration['working_directory'] = f"state_{peer_id}"
        configuration['overlays'] = []

        # Start the IPv8 service
        ipv8 = IPv8(configuration)
        await ipv8.start()
        rest_manager = RESTManager(ipv8)

        # We REALLY want this particular port, keep trying
        keep_trying = True
        while keep_trying:
            try:
                await rest_manager.start(14410 + peer_id)
                keep_trying = False
            except OSError:
                sleep(1.0)  # noqa: ASYNC101

        # Print the peer for reference
        print("Starting peer", b64encode(ipv8.keys["anonymous id"].mid))

    await run_forever()


run(start_community())
