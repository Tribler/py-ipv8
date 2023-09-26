from asyncio import run

from ipv8.configuration import get_default_configuration
from ipv8.util import run_forever
from ipv8_service import IPv8


async def start_ipv8() -> None:
    # Create an IPv8 object with the default settings.
    ipv8 = IPv8(get_default_configuration())
    await ipv8.start()

    # Wait forever (or until the user presses Ctrl+C)
    await run_forever()

    # Shutdown IPv8. To keep things simple, we won't stop IPv8 in the remainder of the tutorial.
    await ipv8.stop()

# Create a new event loop and run a task that starts an IPv8 instance.
run(start_ipv8())
