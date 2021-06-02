Running simulations with IPv8
=============================

In this tutorial we describe how to run simulations with IPv8. Running simulations can be convenient if a developer quickly wants to test out some overlay communication without consuming local resources (e.g., network sockets), or when replaying longitudinal data traces. Simulations provide granular control over the experiment and allows for advanced customization, e.g., simulating network latencies between peers.

All code associated with simulations are provided in the `simulation` package. IPv8 simulation uses a customized asyncio event loop to ensure that commands (e.g., `asyncio.sleep(2)`) proceed in single time steps without actually waiting for the same real-time period. The source code for this functionality can be found in the `discrete_loop.py` file in the `simulation` package.

Code Example
------------

Below we provide a Python snippet that runs a simple simulation. In this example, we start two IPv8 instances with a `SimulatedEndpoint` as endpoint. Like the unit tests, the LAN/WAN addresses are randomly generated. Each instance loads a single `PingPongCommunity` overlay and peers are introduced to each other after IPv8 has started. Each peer sends a ping message to the other peer every two seconds. The sending and reception of ping and pong message are printed to standard output, together with the current time of the event loop. The simulation ends after ten seconds.

.. literalinclude:: simulation_tutorial_1.py