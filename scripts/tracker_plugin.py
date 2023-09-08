"""
This script enables to start the tracker.

Select the port you want to use by setting the `listen_port` command line argument.
"""
import argparse
import sys
from asyncio import run

# Check if we are running from the root directory
# If not, modify our path so that we can import IPv8
try:
    import ipv8
    del ipv8
except ImportError:
    import __scriptpath__  # noqa: F401

from tracker_service import TrackerService

from ipv8.util import run_forever


async def main() -> None:
    """
    Start a tracker service with some given commandline arguments.
    """
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
    await service.start_tracker(args.listen_port)
    if args.listen_port_api >= 0:
        await service.start_api(args.listen_port_api, args.api_key, args.cert_file)
    await run_forever()
    await service.shutdown()


if __name__ == "__main__":
    run(main())
