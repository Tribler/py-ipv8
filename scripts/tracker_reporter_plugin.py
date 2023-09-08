"""
This script enables to start the tracker which reports anonymized statistics.

Select the port you want to use by setting the `listen_port` command line argument.
"""
import argparse
import sys
from asyncio import run

from trackermetricsreporter import MetricsReporter

# Check if we are running from the root directory
# If not, modify our path so that we can import IPv8
try:
    import ipv8
    del ipv8
except ImportError:
    import __scriptpath__  # noqa: F401

from tracker_service import EndpointServer, TrackerService

from ipv8.types import Address, Endpoint, Peer
from ipv8.util import run_forever


class ReportingEndpointServer(EndpointServer):
    """
    Extend the tracker community by adding a reporter that listens in on all incoming introduction requests.
    """

    def __init__(self, endpoint: Endpoint, reporter: MetricsReporter) -> None:
        """
        Create a new server that notifies the given reporter.
        """
        super().__init__(endpoint)
        self.reporter = reporter

    def on_peer_introduction_request(self, peer: Peer, source_address: Address, service_id: bytes) -> None:
        """
        Callback for when a peer has sent an introduction request.
        """
        self.reporter.count_peer(peer.mid, source_address, service_id)


class ReportingTrackerService(TrackerService):
    """
    Extend the tracker service by adding a reporter that listens in on all incoming introduction requests.
    """

    def __init__(self, reporter: MetricsReporter) -> None:
        """
        Create a new service that notifies the given reporter.
        """
        super().__init__()
        self.reporter = reporter

    def create_endpoint_server(self) -> EndpointServer:
        """
        Instantiate our reporting Community.
        """
        return ReportingEndpointServer(self.endpoint, self.reporter)


async def main() -> None:
    """
    Start an reporting tracker service with some given commandline arguments.
    """
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
