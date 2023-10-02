import json
import os
from asyncio import Event, run
from binascii import hexlify, unhexlify

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.types import Address, Peer
from ipv8_service import IPv8


def to_hex(bstr: bytes) -> str:
    return hexlify(bstr).decode()


class MyCommunity(Community):
    community_id = os.urandom(20)

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.event = None
        self.add_message_handler(1, self.on_message)

    def send_message(self, peer: Peer) -> None:
        message = json.dumps({"key": "value", "key2": "value2"})
        public_key = to_hex(self.my_peer.public_key.key_to_bin())
        signature = to_hex(self.my_peer.key.signature(message.encode()))

        signed_message = json.dumps({"message": message,
                                     "public_key": public_key,
                                     "signature": signature}).encode()
        self.endpoint.send(peer.address,
                           self.get_prefix() + b'\x01' + signed_message)

    def on_message(self, source_address: Address, data: bytes) -> None:
        # Account for 1 byte message id
        header_length = len(self.get_prefix()) + 1
        # Strip the IPv8 multiplexing data
        received = json.loads(data[header_length:])

        public_key = self.crypto.key_from_public_bin(unhexlify(received["public_key"]))
        valid = self.crypto.is_valid_signature(public_key,
                                               received["message"].encode(),
                                               unhexlify(received["signature"]))
        self.logger.info("Received message %s from %s, the signature is %s!",
                         received['message'], source_address, valid)

        if self.event:
            self.event.set()

    def started(self, event: Event, peer_id: int) -> None:
        self.event = event

        async def send_message() -> None:
            for p in self.get_peers():
                self.send_message(p)

        if peer_id == 1:
            self.register_task("Start Sending Messages", send_message, interval=2.0, delay=0)


async def start_communities() -> None:
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
