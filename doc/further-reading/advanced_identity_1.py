from asyncio import ensure_future, get_event_loop
from base64 import b64encode

from pyipv8.ipv8.REST.rest_manager import RESTManager
from pyipv8.ipv8.configuration import get_default_configuration
from pyipv8.ipv8_service import IPv8


async def start_community():
    for peer_id in [1, 2]:
        configuration = get_default_configuration()
        configuration['keys'] = [
            {'alias': "anonymous id", 'generation': u"curve25519", 'file': f"keyfile_{peer_id}.pem"}]
        configuration['working_directory'] = f"state_{peer_id}"
        configuration['overlays'] = [overlay for overlay in configuration['overlays']
                                     if overlay['class'] == 'HiddenTunnelCommunity']

        # Start the IPv8 service
        ipv8 = IPv8(configuration)
        await ipv8.start()
        rest_manager = RESTManager(ipv8)
        await rest_manager.start(14410 + peer_id, api_key="my secret key")

        # Print the peer for reference
        print("Starting peer", b64encode(ipv8.keys["anonymous id"].mid))


ensure_future(start_community())
get_event_loop().run_forever()
