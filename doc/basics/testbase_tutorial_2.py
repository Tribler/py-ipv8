import os
import unittest
from dataclasses import dataclass
from random import random, shuffle

from pyipv8.ipv8.community import Community, DEFAULT_MAX_PEERS
from pyipv8.ipv8.lazy_community import lazy_wrapper, lazy_wrapper_unsigned
from pyipv8.ipv8.messaging.payload_dataclass import overwrite_dataclass
from pyipv8.ipv8.test.base import TestBase

dataclass = overwrite_dataclass(dataclass)


@dataclass(msg_id=1)
class Message1:
    value: int


@dataclass(msg_id=2)
class Message2:
    value: int


@dataclass(msg_id=3)
class Message3:
    value: int


class MyCommunity(Community):
    community_id = os.urandom(20)

    def __init__(self, my_peer, endpoint, network, max_peers=DEFAULT_MAX_PEERS, anonymize=False):
        super().__init__(my_peer, endpoint, network, max_peers, anonymize)

        self.add_message_handler(Message1, self.on_message1)
        self.add_message_handler(Message2, self.on_message2)
        self.add_message_handler(Message3, self.on_message3)

    @lazy_wrapper(Message1)
    def on_message1(self, peer, payload):
        pass

    @lazy_wrapper_unsigned(Message2)
    def on_message2(self, peer, payload):
        pass

    @lazy_wrapper(Message3)
    def on_message3(self, peer, payload):
        pass

    def send_msg_to(self, peer, message_number):
        if message_number == 1:
            self.ez_send(peer, Message1(1), sig=True)
        elif message_number == 2:
            self.ez_send(peer, Message2(2), sig=False)
        elif message_number == 3:
            self.ez_send(peer, Message3(3), sig=True)


class TestMyCommunity(TestBase):

    def setUp(self):
        super().setUp()
        self.initialize(MyCommunity, 2)

    async def test_received_default(self):
        with self.assertReceivedBy(1, [Message1, Message2]):
            self.overlay(0).send_msg_to(self.peer(1), 1)
            self.overlay(0).send_msg_to(self.peer(1), 2)
            await self.deliver_messages()

    async def test_received_no_order(self):
        with self.assertReceivedBy(1, [Message1] + 2 * [Message2], ordered=False):
            messages = [2, 1, 2]
            shuffle(messages)
            self.overlay(0).send_msg_to(self.peer(1), messages[0])
            self.overlay(0).send_msg_to(self.peer(1), messages[1])
            self.overlay(0).send_msg_to(self.peer(1), messages[2])
            await self.deliver_messages()

    async def test_received_filter(self):
        with self.assertReceivedBy(1, [Message1, Message2], message_filter=[Message1, Message2]):
            self.overlay(0).send_msg_to(self.peer(1), 1)
            if random() > 0.5:
                self.overlay(0).send_msg_to(self.peer(1), 3)
            self.overlay(0).send_msg_to(self.peer(1), 2)
            await self.deliver_messages()

    async def test_received_result(self):
        with self.assertReceivedBy(1, [Message1, Message2]) as received_messages:
            self.overlay(0).send_msg_to(self.peer(1), 1)
            self.overlay(0).send_msg_to(self.peer(1), 2)
            await self.deliver_messages()

        message1, message2 = received_messages
        self.assertEqual(1, message1.value)
        self.assertEqual(2, message2.value)


if __name__ == '__main__':
    unittest.main()
