from asyncio import run, sleep
from itertools import combinations
from typing import cast

from ipv8.configuration import ConfigBuilder
from ipv8.dht import DHTError
from ipv8.dht.community import DHTCommunity
from ipv8.dht.discovery import DHTDiscoveryCommunity
from ipv8.peer import Peer
from ipv8_service import IPv8


async def main() -> None:
    instances = []

    # Put some peers in the network
    for _ in range(10):
        config = ConfigBuilder().clear_keys()
        config.config["overlays"] = [o for o in config.config["overlays"] if o["class"] == "DHTDiscoveryCommunity"]
        config.add_ephemeral_key("anonymous id")
        config.set_address("127.0.0.1")  # We don't want this test to connect to the actual network!
        ipv8 = IPv8(config.finalize())
        instances.append(ipv8)
        await ipv8.start()

    # Supercharge introductions, normally this takes longer
    for id1, id2 in combinations(range(10), 2):
        overlay1 = instances[id1].get_overlay(DHTCommunity)
        overlay2 = instances[id2].get_overlay(DHTCommunity)
        peer1 = Peer(overlay2.my_peer.public_key.key_to_bin(), ("127.0.0.1", overlay2.my_estimated_lan[1]))
        peer1.address_frozen = True
        peer2 = Peer(overlay1.my_peer.public_key.key_to_bin(), ("127.0.0.1", overlay1.my_estimated_lan[1]))
        peer2.address_frozen = True
        overlay1.network.add_verified_peer(peer2)
        overlay1.get_requesting_node(peer2)
        overlay2.network.add_verified_peer(peer1)
        overlay2.get_requesting_node(peer1)
    for i in range(10):
        await instances[i].get_overlay(DHTDiscoveryCommunity).store_peer()
        instances[i].get_overlay(DHTDiscoveryCommunity).ping_all()

    dht_community = cast("DHTCommunity", instances[0].get_overlay(DHTCommunity))
    try:
        await dht_community.store_value(b"my key", b"my value", True)
        print(dht_community.my_peer.public_key.key_to_bin(), "published b'my value' under b'my key'!")
    except DHTError as e:
        print("Failed to store my value under my key!", e)

    try:
        results = await dht_community.find_values(b"my key")
        print(f"We got results from {len(results)} peers!")
        for value, signer_key in results:
            print(f"The value {value} was found, signed by {signer_key}")
    except DHTError as e:
        print("Failed to find key!", e)

    dht_discovery_community = cast("DHTDiscoveryCommunity", instances[7].get_overlay(DHTDiscoveryCommunity))
    some_peer_mid = instances[2].keys["anonymous id"].mid
    while True:
        try:
            await sleep(0.5)
            await dht_discovery_community.connect_peer(some_peer_mid)
            break
        except DHTError as e:
            print("Failed to connect to peer!", e)

run(main())
