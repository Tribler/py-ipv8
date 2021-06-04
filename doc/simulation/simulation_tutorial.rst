Running simulations with IPv8
=============================

In this tutorial we describe how to run simulations with IPv8. Running simulations can be convenient if a developer quickly wants to test out some overlay communication without consuming local resources (e.g., network sockets), or when replaying longitudinal data traces. Simulations provide granular control over the experiment and allows for advanced customization, e.g., simulating network latencies between peers.

All code associated with simulations are provided in the `simulation` package. IPv8 simulation uses a customized asyncio event loop to ensure that commands (e.g., `asyncio.sleep(2)`) proceed in single time steps without actually waiting for the same real-time period. The source code for this functionality can be found in the `discrete_loop.py` file in the `simulation` package.

Code Example
------------

Below we provide a Python snippet that runs a simple simulation. In this example, we start two IPv8 instances with a `SimulatedEndpoint` as endpoint. Like the unit tests, the LAN/WAN addresses of peers are randomly generated and any communication to a peer that is not part of our simulation will raise an exception. Each instance loads a single `PingPongCommunity` overlay and peers are introduced to each other after IPv8 has started. Each peer sends a ping message to the other peer every two seconds. The sending and reception of ping and pong message are printed to standard output, together with the current time of the event loop. The simulation ends after ten seconds.

.. literalinclude:: simulation_tutorial_1.py

The endpoint used in the above code assumes that packets arrive immediately at the recipient. This is unrealistic in deployed peer-to-peer networks where link latency can be considerable, especially when considering communication between peers in different continents. Developers can simulate link latencies by modifying the `latencies` class variable, or by overriding the `get_link_latency` method. Link latencies can, for example, be set to random values or be determined by a latency matrix.

Using the Bootstrap Server
--------------------------

In the example above, we explicitly introduce peers to each other by sending introduction requests between all pairs of peers. While this ensures full connectivity, it might not reflect the behaviours in deployed networks where peer discovery is a gradual and dynamic process. Peer discovery in IPv8 is assisted by bootstrap servers that maintain knowledge of the current active peers in the network and are able to introduce (a few) peers to newly joined peers to get them started.

Below we show a Python snippet running a simple simulation with two simulated bootstrap servers and 20 peers. The experiments simulates a period of two minutes and every two seconds, a peer prints how many other peers it has discovered. When the simulation ends, each peer knows around ten other peers. Note that we also add a `RandomWalk` strategy to each initialized community.

.. literalinclude:: simulation_tutorial_2.py
