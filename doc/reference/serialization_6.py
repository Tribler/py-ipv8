from binascii import hexlify, unhexlify
import json
import os
from asyncio import Event, run

from pyipv8.ipv8.community import Community
from pyipv8.ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from pyipv8.ipv8_service import IPv8


class MyCommunity(Community):
    community_id = os.urandom(20)

    def __init__(self, my_peer, endpoint, network):
        super().__init__(my_peer, endpoint, network)
        self.event = None
        self.add_message_handler(1, self.on_message)

    def send_message(self, peer):
        message = json.dumps({"key": "value", "key2": "value2"})
        public_key = hexlify(self.my_peer.public_key.key_to_bin()).decode()
        signature = hexlify(self.my_peer.key.signature(message.encode())).decode()

        signed_message = json.dumps({"message": message,
                                     "public_key": public_key,
                                     "signature": signature}).encode()
        self.endpoint.send(peer.address, self.get_prefix() + b'\x01' + signed_message)

    def on_message(self, source_address, data):
        header_length = len(self.get_prefix()) + 1  # Account for 1 byte message id
        received = json.loads(data[header_length:])  # Strip the IPv8 multiplexing data

        public_key = self.crypto.key_from_public_bin(unhexlify(received["public_key"]))
        valid = self.crypto.is_valid_signature(public_key,
                                               received["message"].encode(),
                                               unhexlify(received["signature"]))
        self.logger.info(f"Received message {received['message']} from {source_address},"
                         f"the signature is {valid}!")

        if self.event:
            self.event.set()

    def started(self, event, peer_id):
        self.event = event

        async def send_message():
            for p in self.get_peers():
                self.send_message(p)

        if peer_id == 1:
            self.register_task("Start Sending Messages", send_message, interval=2.0, delay=0)


async def start_communities():
    event = Event()

    for i in [1, 2]:
        builder = ConfigBuilder().clear_keys().clear_overlays()
        builder.add_key("my peer", "medium", f"ec{i}.pem")
        builder.add_overlay("MyCommunity", "my peer", [WalkerDefinition(Strategy.RandomWalk, 10, {'timeout': 3.0})],
                            default_bootstrap_defs, {}, [("started", event, i)])
        ipv8 = IPv8(builder.finalize(), extra_communities={'MyCommunity': MyCommunity})
        await ipv8.start()

    await event.wait()


run(start_communities())
