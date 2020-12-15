"""
This script enables to start the tracker which reports anonymized statistics.

Select the port you want to use by setting the `listen_port` command line argument.
"""
import argparse
import sys
from asyncio import ensure_future, get_event_loop, sleep

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


def main(argv):
    parser = argparse.ArgumentParser(add_help=False, description='IPv8 tracker plugin which reports anonymized stats')
    parser.add_argument('--help', '-h', action='help', default=argparse.SUPPRESS, help='Show this help message and exit')
    parser.add_argument('--listen_port', '-p', default=8090, type=int, help='Use an alternative port')

    args = parser.parse_args(sys.argv[1:])
    listen_port = args.listen_port
    reporter = MetricsReporter(listen_port)
    service = ReportingTrackerService(reporter)

    loop = get_event_loop()

    coro = service.start_tracker(listen_port)
    ensure_future(coro)

    if sys.platform == 'win32':
        # Unfortunately, this is needed on Windows for Ctrl+C to work consistently.
        # Should no longer be needed in Python 3.8.
        async def wakeup():
            while True:
                await sleep(1)
        ensure_future(wakeup())

    reporter.start()
    try:
        loop.run_forever()
    finally:
        reporter.shutdown()


if __name__ == "__main__":
    main(sys.argv[1:])
