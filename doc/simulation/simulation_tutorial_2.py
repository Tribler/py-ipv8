import os
from asyncio import run, set_event_loop, sleep

from pyipv8.ipv8.community import Community
from pyipv8.ipv8.configuration import Bootstrapper, BootstrapperDefinition, ConfigBuilder, Strategy, WalkerDefinition
from pyipv8.ipv8_service import IPv8
from pyipv8.scripts.tracker_service import EndpointServer
from pyipv8.simulation.discrete_loop import DiscreteLoop
from pyipv8.simulation.simulation_endpoint import SimulationEndpoint


class SimpleCommunity(Community):
    """
    Very basic community that just prints the number of known peers every two seconds.
    """
    community_id = os.urandom(20)

    def __init__(self, my_peer, endpoint, network, **kwargs):
        super().__init__(my_peer, endpoint, network)
        self.id = kwargs.pop('id')

    def started(self):
        self.register_task("print_peers", self.print_peers, interval=2.0, delay=0)

    def print_peers(self):
        self._logger.info("I am peer %d, I know %d peers...", self.id, len(self.network.verified_peers))


async def start_communities():
    bootstrap_ips = []
    for i in range(2):  # We start two bootstrap nodes
        bootstrap_endpoint = SimulationEndpoint()
        await bootstrap_endpoint.open()
        bootstrap_overlay = EndpointServer(bootstrap_endpoint)

        # We assume all peers in our simulation have a public WAN IP (to avoid conflicts with our SimulationEndpoint)
        bootstrap_overlay.my_estimated_lan = ("0.0.0.0", 0)
        bootstrap_overlay.my_estimated_wan = bootstrap_endpoint.wan_address
        bootstrap_ips.append(bootstrap_endpoint.wan_address)

    instances = []
    for i in range(20):
        builder = ConfigBuilder().clear_keys().clear_overlays()
        builder.add_key("my peer", "medium", f"ec{i}.pem")
        bootstrappers = [BootstrapperDefinition(Bootstrapper.DispersyBootstrapper,
                                                {"ip_addresses": bootstrap_ips, "dns_addresses": []})]
        walkers = [WalkerDefinition(Strategy.RandomWalk, 10, {'timeout': 3.0})]
        builder.add_overlay("SimpleCommunity", "my peer", walkers, bootstrappers, {'id': i}, [('started',)])

        endpoint = SimulationEndpoint()
        instance = IPv8(builder.finalize(), endpoint_override=endpoint,
                        extra_communities={'SimpleCommunity': SimpleCommunity})
        # We assume all peers in our simulation have a public WAN IP (to avoid conflicts with our SimulationEndpoint)
        instance.overlays[0].my_estimated_lan = ("0.0.0.0", 0)
        instance.overlays[0].my_estimated_wan = endpoint.wan_address
        await instance.start()
        instances.append(instance)

    await sleep(120)


# We use a discrete event loop to enable quick simulations.
loop = DiscreteLoop()
set_event_loop(loop)

run(start_communities())
