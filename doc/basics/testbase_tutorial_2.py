import os
import unittest
from random import random, shuffle

from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper, lazy_wrapper_unsigned
from ipv8.messaging.payload_dataclass import dataclass
from ipv8.test.base import TestBase
from ipv8.types import Peer


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

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)

        self.add_message_handler(Message1, self.on_message1)
        self.add_message_handler(Message2, self.on_message2)
        self.add_message_handler(Message3, self.on_message3)

    @lazy_wrapper(Message1)
    def on_message1(self, peer: Peer, payload: Message1) -> None:
        pass

    @lazy_wrapper_unsigned(Message2)
    def on_message2(self, peer: Peer, payload: Message2) -> None:
        pass

    @lazy_wrapper(Message3)
    def on_message3(self, peer: Peer, payload: Message3) -> None:
        pass

    def send_msg_to(self, peer: Peer, message_number: int) -> None:
        if message_number == 1:
            self.ez_send(peer, Message1(1), sig=True)
        elif message_number == 2:
            self.ez_send(peer, Message2(2), sig=False)
        elif message_number == 3:
            self.ez_send(peer, Message3(3), sig=True)


class TestMyCommunity(TestBase):

    def setUp(self) -> None:
        super().setUp()
        self.initialize(MyCommunity, 2)

    async def test_received_default(self) -> None:
        with self.assertReceivedBy(1, [Message1, Message2]):
            self.overlay(0).send_msg_to(self.peer(1), 1)
            self.overlay(0).send_msg_to(self.peer(1), 2)
            await self.deliver_messages()

    async def test_received_no_order(self) -> None:
        with self.assertReceivedBy(1, [Message1, Message2, Message2], ordered=False):
            messages = [2, 1, 2]
            shuffle(messages)
            self.overlay(0).send_msg_to(self.peer(1), messages[0])
            self.overlay(0).send_msg_to(self.peer(1), messages[1])
            self.overlay(0).send_msg_to(self.peer(1), messages[2])
            await self.deliver_messages()

    async def test_received_filter(self) -> None:
        with self.assertReceivedBy(1, [Message1, Message2], message_filter=[Message1, Message2]):
            self.overlay(0).send_msg_to(self.peer(1), 1)
            if random() > 0.5:
                self.overlay(0).send_msg_to(self.peer(1), 3)
            self.overlay(0).send_msg_to(self.peer(1), 2)
            await self.deliver_messages()

    async def test_received_result(self) -> None:
        with self.assertReceivedBy(1, [Message1, Message2]) as received_messages:
            self.overlay(0).send_msg_to(self.peer(1), 1)
            self.overlay(0).send_msg_to(self.peer(1), 2)
            await self.deliver_messages()

        message1, message2 = received_messages
        self.assertEqual(1, message1.value)
        self.assertEqual(2, message2.value)


if __name__ == '__main__':
    unittest.main()
