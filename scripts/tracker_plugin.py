"""
This script enables to start the tracker.

Select the port you want to use by setting the `listen_port` command line argument.
"""
import argparse
import sys
from asyncio import ensure_future, get_event_loop, sleep


from tracker_service import TrackerService


def main(argv):
    parser = argparse.ArgumentParser(add_help=False, description=('IPv8 tracker plugin'))
    parser.add_argument('--help', '-h', action='help', default=argparse.SUPPRESS, help='Show this help message and exit')
    parser.add_argument('--listen_port', '-p', default=8090, type=int, help='Use an alternative port')

    args = parser.parse_args(sys.argv[1:])
    service = TrackerService()

    loop = get_event_loop()
    coro = service.start_tracker(args.listen_port)
    ensure_future(coro)

    if sys.platform == 'win32':
        # Unfortunately, this is needed on Windows for Ctrl+C to work consistently.
        # Should no longer be needed in Python 3.8.
        async def wakeup():
            while True:
                await sleep(1)
        ensure_future(wakeup())

    loop.run_forever()


if __name__ == "__main__":
    main(sys.argv[1:])
