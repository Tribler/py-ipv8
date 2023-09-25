from __future__ import annotations

from asyncio import FIRST_COMPLETED, Future, wait
from statistics import mean, median
from timeit import default_timer
from typing import TYPE_CHECKING, Set

from .tunnel import CIRCUIT_STATE_CLOSING, Circuit

if TYPE_CHECKING:
    from .community import TunnelCommunity


async def run_speed_test(tc: TunnelCommunity, circuit: Circuit, request_size: int, response_size: int,
                         num_requests: int, window: int = 50) -> dict[str, int | float]:
    """
    Test a circuit's speed.
    """
    num_sent = 0
    num_ack = 0
    outstanding: Set[Future[tuple[bytes, float]]] = set()
    start = default_timer()
    rtts = []

    while True:
        while num_sent < num_requests and len(outstanding) < window and circuit.state != CIRCUIT_STATE_CLOSING:
            outstanding.add(tc.send_test_request(circuit, request_size, response_size))
            num_sent += 1
        if not outstanding:
            break
        done, outstanding = await wait(outstanding, return_when=FIRST_COMPLETED, timeout=10)
        if not done:
            # We have received nothing for the past 10s.Any pending messages are considered lost.
            break
        # Make sure to only count futures that haven't been set by on_timeout.
        results = [f.result() for f in done if f.result() is not None]
        num_ack += len(results)
        rtts.extend([rtt for _, rtt in results])

    return {'speed_up': (num_ack * request_size / 1024) / (default_timer() - start),
            'speed_down': (num_ack * response_size / 1024) / (default_timer() - start),
            'messages_sent': num_ack + len(outstanding),
            'messages_received': num_ack,
            'rtt_mean': mean(rtts) if rtts else -1,
            'rtt_median': median(rtts) if rtts else -1}
