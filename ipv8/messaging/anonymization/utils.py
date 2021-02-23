from asyncio import FIRST_COMPLETED, wait
from statistics import mean, median
from timeit import default_timer

from ipv8.messaging.anonymization.tunnel import CIRCUIT_STATE_CLOSING, EXIT_NODE, ORIGINATOR


async def run_speed_test(tc, direction, circuit, window=50, size=30):
    assert direction in [EXIT_NODE, ORIGINATOR]

    request_size = 0 if direction == ORIGINATOR else 1024
    response_size = 1024 if direction == ORIGINATOR else 0
    # Transfer size * 1024 * 1024 = size MB (excluding protocol overhead).
    num_packets = size * 1024
    num_sent = 0
    num_ack = 0
    outstanding = set()
    start = default_timer()
    rtts = []

    while True:
        while num_sent < num_packets and len(outstanding) < window and circuit.state != CIRCUIT_STATE_CLOSING:
            outstanding.add(tc.send_test_request(circuit, request_size, response_size))
            num_sent += 1
        if not outstanding:
            break
        done, outstanding = await wait(outstanding, return_when=FIRST_COMPLETED, timeout=3)
        if not done and num_ack > 0.95 * num_packets:
            # We have received nothing for the past 3s and did get an acknowledgement for 95%
            # of our requests. To avoid waiting for packets that may never arrive we stop the
            # test. Any pending messages are considered lost.
            break
        # Make sure to only count futures that haven't been set by on_timeout.
        results = [f.result() for f in done if f.result() is not None]
        num_ack += len(results)
        rtts.extend([rtt for _, rtt in results])

    return {'speed': (num_ack / 1024) / (default_timer() - start),
            'messages_sent': num_ack + len(outstanding),
            'messages_received': num_ack,
            'rtt_mean': mean(rtts),
            'rtt_median': median(rtts)}
