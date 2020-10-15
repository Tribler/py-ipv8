from asyncio import ensure_future, get_event_loop

from pyipv8.ipv8.configuration import get_default_configuration
from pyipv8.ipv8_service import IPv8


async def start_ipv8():
    # The first IPv8 will attempt to claim a port.
    await IPv8(get_default_configuration()).start()
    # The second IPv8 will attempt to claim a port.
    # It cannot claim the same port and will end up claiming a different one.
    await IPv8(get_default_configuration()).start()


ensure_future(start_ipv8())
get_event_loop().run_forever()
