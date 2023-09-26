import os
import ssl
import sys
from asyncio import run
from base64 import b64encode

from ipv8.configuration import get_default_configuration
from ipv8.REST.rest_manager import RESTManager
from ipv8.util import run_forever
from ipv8_service import IPv8

cert_file = os.path.join(os.path.dirname(sys.modules[IPv8.__module__].__file__),
                         "doc", "further-reading", "certfile.pem")


async def start_community() -> None:
    for peer_id in [1, 2]:
        configuration = get_default_configuration()
        configuration['keys'] = [
            {'alias': "anonymous id", 'generation': "curve25519", 'file': f"keyfile_{peer_id}.pem"}]
        configuration['working_directory'] = f"state_{peer_id}"
        configuration['overlays'] = [overlay for overlay in configuration['overlays']
                                     if overlay['class'] == 'HiddenTunnelCommunity']

        # Start the IPv8 service
        ipv8 = IPv8(configuration)
        await ipv8.start()
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_file)
        rest_manager = RESTManager(ipv8)
        await rest_manager.start(14410 + peer_id, ssl_context=ssl_context)

        # Print the peer for reference
        print("Starting peer", b64encode(ipv8.keys["anonymous id"].mid))

    await run_forever()


run(start_community())
