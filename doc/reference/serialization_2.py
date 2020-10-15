import os

from pyipv8.ipv8.community import Community
from pyipv8.ipv8.lazy_community import lazy_wrapper
from pyipv8.ipv8.messaging.lazy_payload import VariablePayload, vp_compile


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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.add_message_handler(1, self.on_message)

    @lazy_wrapper(MyMessagePayload1, MyMessagePayload2)
    def on_message(self, peer, payload1, payload2):
        print("Got a message from:", peer)
        print("The message includes the first payload:\n", payload1)
        print("The message includes the second payload:\n", payload2)

    def send_message(self, peer):
        packet = self.ezr_pack(1, MyMessagePayload1(), MyMessagePayload2())
        self.endpoint.send(peer.address, packet)
