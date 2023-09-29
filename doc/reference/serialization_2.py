import os

from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.types import Peer


@vp_compile
class MyMessagePayload1(VariablePayload):
    format_list = []
    names = []


@vp_compile
class MyMessagePayload2(VariablePayload):
    format_list = []
    names = []


COMMUNITY_ID = os.urandom(20)


class MyCommunity(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)

        self.add_message_handler(1, self.on_message)

    @lazy_wrapper(MyMessagePayload1, MyMessagePayload2)
    def on_message(self, peer: Peer, payload1: MyMessagePayload1,
                   payload2: MyMessagePayload2) -> None:
        print("Got a message from:", peer)
        print("The message includes the first payload:\n", payload1)
        print("The message includes the second payload:\n", payload2)

    def send_message(self, peer: Peer) -> None:
        packet = self.ezr_pack(1, MyMessagePayload1(), MyMessagePayload2())
        self.endpoint.send(peer.address, packet)
