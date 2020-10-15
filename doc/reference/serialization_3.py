import os

from pyipv8.ipv8.community import Community
from pyipv8.ipv8.lazy_community import lazy_wrapper
from pyipv8.ipv8.messaging.lazy_payload import VariablePayload, vp_compile


@vp_compile
class MyMessage1(VariablePayload):
    msg_id = 1
    format_list = ['I']
    names = ['unsigned_integer_field']


@vp_compile
class MyMessage2(VariablePayload):
    msg_id = 2
    format_list = ['I']
    names = ['unsigned_integer_field']


COMMUNITY_ID = os.urandom(20)


class MyCommunity(Community):
    community_id = COMMUNITY_ID

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.add_message_handler(MyMessage1, self.on_message1)
        self.add_message_handler(MyMessage2, self.on_message2)

    @lazy_wrapper(MyMessage1)
    def on_message1(self, peer, payload):
        print("Got a message from:", peer)
        print("The message includes the first payload:\n", payload)

    @lazy_wrapper(MyMessage2)
    def on_message2(self, peer, payload):
        print("Got a message from:", peer)
        print("The message includes the first payload:\n", payload)

    def send_message1(self, peer):
        packet = self.ezr_pack(MyMessage1.msg_id, MyMessage1(42))
        self.endpoint.send(peer.address, packet)

    def send_message2(self, peer):
        packet = self.ezr_pack(MyMessage2.msg_id, MyMessage2(7))
        self.endpoint.send(peer.address, packet)

    def better_send_message_1(self, peer):
        self.ez_send(peer, MyMessage1(42))

    def better_send_message_2(self, peer):
        self.ez_send(peer, MyMessage2(7))
