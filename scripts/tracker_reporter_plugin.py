"""
This script enables to start the tracker which reports anonymized statistics.

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

from ipv8.util import run_forever

from trackermetricsreporter import MetricsReporter

from tracker_service import EndpointServer, TrackerService


class ReportingEndpointServer(EndpointServer):
    def __init__(self, endpoint, reporter):
        super().__init__(endpoint)
        self.reporter = reporter

    def on_peer_introduction_request(self, peer, source_address, service_id):
        self.reporter.count_peer(peer.mid, source_address, service_id)


class ReportingTrackerService(TrackerService):

    def __init__(self, reporter):
        super().__init__()
        self.reporter = reporter

    def create_endpoint_server(self):
        return ReportingEndpointServer(self.endpoint, self.reporter)


async def main():
    parser = argparse.ArgumentParser(
        add_help=False,
        description='IPv8 tracker plugin which reports anonymized stats')
    parser.add_argument('--help', '-h', action='help',
                        default=argparse.SUPPRESS,
                        help='Show this help message and exit')
    parser.add_argument('--listen_port', '-p', default=8090, type=int,
                        help='Use an alternative port')

    args = parser.parse_args(sys.argv[1:])
    listen_port = args.listen_port

    reporter = MetricsReporter(listen_port)
    service = ReportingTrackerService(reporter)

    await service.start_tracker(listen_port)
    reporter.start()

    await run_forever()

    await service.shutdown()
    reporter.shutdown()


if __name__ == "__main__":
    run(main())
