import json
import os
import struct
from asyncio import Event, run
from typing import Any

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.messaging.serialization import Packer, Serializer
from ipv8.types import Peer
from ipv8_service import IPv8


@vp_compile
class Message(VariablePayload):
    msg_id = 1
    format_list = ['json', 'json', 'json', 'json']
    names = ["d1", "d2", "d3", "d4"]


class PackerJSON(Packer):

    def pack(self, data: Any) -> bytes:
        packed = json.dumps(data).encode()
        size = struct.pack(">H", len(packed))
        return size + packed

    def unpack(self, data: bytes, offset: int,
               unpack_list: list, *args: Any) -> int:
        size, = struct.unpack_from(">H", data, offset)

        json_data_start = offset + 2
        json_data_end = json_data_start + size

        serialized = data[json_data_start:json_data_end]
        unpack_list.append(json.loads(serialized))

        return json_data_end


class MyCommunity(Community):

    def get_serializer(self) -> Serializer:
        serializer = super().get_serializer()
        serializer.add_packer('json', PackerJSON())
        return serializer

    community_id = os.urandom(20)

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.event = None
        self.add_message_handler(Message, self.on_message)

    @lazy_wrapper(Message)
    def on_message(self, peer: Peer, message: Message) -> None:
        self.logger.info(str(peer))
        self.logger.info(str(message))

        assert message.d4 == 1337  # Check d4 here to make sure this is not some magic temporary serialization.

        if self.event:
            self.event.set()

    def started(self, event: Event, peer_id: int) -> None:
        self.event = event

        async def send_message() -> None:
            for p in self.get_peers():
                message = Message(
                    {"a": "b", "c": "d"},
                    {"e": "f", "g": "h"},
                    ["i", "j", "k", "l"],
                    42
                )
                message.d4 = 1337  # Overwrite 42 here to make sure this is not some magic temporary serialization.
                self.ez_send(p, message)

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
