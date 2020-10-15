from asyncio import ensure_future, get_event_loop

from pyipv8.ipv8.configuration import get_default_configuration
from pyipv8.ipv8_service import IPv8


async def start_ipv8():
    # Create an IPv8 object with the default settings.
    ipv8 = IPv8(get_default_configuration())
    await ipv8.start()

# Create a task that runs an IPv8 instance.
# The task will run as soon as the event loop has started.
ensure_future(start_ipv8())

# Start the asyncio event loop: this is the engine scheduling all of the
# asynchronous calls.
get_event_loop().run_forever()
