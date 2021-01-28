"""
This script enables to start the tracker.

Select the port you want to use by setting the `listen_port` command line argument.
"""
import argparse
import sys
from asyncio import ensure_future, get_event_loop, sleep


from tracker_service import TrackerService


def main():
    parser = argparse.ArgumentParser(add_help=False,
                                     description='IPv8 tracker plugin')
    parser.add_argument('--help', '-h', action='help',
                        default=argparse.SUPPRESS,
                        help='Show this help message and exit')
    parser.add_argument('--listen_port', '-p', default=8090, type=int,
                        help='Use an alternative IPv8 port')
    parser.add_argument('--listen_port_api', '-a', default=-1, type=int,
                        help='Use an alternative API port')
    parser.add_argument('--api_key', '-k',
                        help='API key to use. If not given API key protection is disabled.')
    parser.add_argument('--cert_file', '-c',
                        help='Path to combined certificate/key file. If not given HTTP is used.')

    args = parser.parse_args(sys.argv[1:])
    service = TrackerService()

    loop = get_event_loop()
    ensure_future(service.start_tracker(args.listen_port))
    if args.listen_port_api >= 0:
        ensure_future(service.start_api(args.listen_port_api, args.api_key, args.cert_file))

    if sys.platform == 'win32':
        # Unfortunately, this is needed on Windows for Ctrl+C to work consistently.
        # Should no longer be needed in Python 3.8.
        async def wakeup():
            while True:
                await sleep(1)
        ensure_future(wakeup())

    loop.run_forever()


if __name__ == "__main__":
    main()
