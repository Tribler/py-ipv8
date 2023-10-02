from __future__ import annotations

import random
import time
from collections import deque
from typing import TYPE_CHECKING, List, cast

from ...community import Community, CommunitySettings
from ...messaging.anonymization.tunnel import PEER_SOURCE_PEX, IntroductionPoint
from ...peer import Peer

if TYPE_CHECKING:
    from ...types import Address
    from ..payload import (
        IntroductionRequestPayload,
        IntroductionResponsePayload,
        NewIntroductionRequestPayload,
        NewIntroductionResponsePayload,
    )
    from ..payload_headers import GlobalTimeDistributionPayload

PEX_VERSION = 1


class PexSettings(CommunitySettings):
    """
    Settings for the PexCommunity.
    """

    info_hash: bytes


class PexCommunity(Community):
    """
    New on-the-fly overlay for the PEX protocol.
    """

    def __init__(self, settings: PexSettings) -> None:
        """
        Create a new PEX community by deriving the community id from the given SHA-1 hash.
        """
        infohash = settings.info_hash
        self.community_id = (int.from_bytes(infohash, 'big') + PEX_VERSION).to_bytes(20, 'big')
        self._prefix = b'\x00' + self.version + self.community_id
        super().__init__(settings)

        self.intro_points: deque[IntroductionPoint] = deque(maxlen=20)
        self.intro_points_for: list[bytes] = []

    def get_intro_points(self) -> list[IntroductionPoint]:
        """
        Get a list of the most recent introduction points that were discovered using PexCommunity.
        :return : list of IntroductionPoint objects.
        """
        # Remove old introduction points
        now = time.time()
        while self.intro_points and self.intro_points[-1].last_seen + 300 < now:
            self.intro_points.pop()

        my_peer = Peer(self.my_peer.key, self.my_estimated_wan)
        return list(self.intro_points) + [IntroductionPoint(my_peer, seeder_pk, PEER_SOURCE_PEX)
                                          for seeder_pk in self.intro_points_for]

    def start_announce(self, seeder_pk: bytes) -> None:
        """
        Start announcing yourself as an introduction point for a certain seeder.

        :param seeder_pk: public key of the seeder (in binary format).
        """
        if seeder_pk not in self.intro_points_for:
            self.intro_points_for.append(seeder_pk)

    def stop_announce(self, seeder_pk: bytes) -> None:
        """
        Stop announcing yourself as an introduction point for a certain seeder.
        :param seeder_pk: public key of the seeder (in binary format).
        """
        if seeder_pk in self.intro_points_for:
            self.intro_points_for.remove(seeder_pk)

    @property
    def done(self) -> bool:
        """
        Check if we have introduction points left.
        """
        return not bool(self.intro_points_for)

    def process_extra_bytes(self, peer: Peer, extra_bytes: bytes) -> None:
        """
        Unpack any introduction points piggybacked onto the introduction requests and responses.
        """
        if not extra_bytes:
            return

        for seeder_pk in cast(List[bytes], self.serializer.unpack('varlenH-list', extra_bytes)[0]):
            ip = IntroductionPoint(peer, seeder_pk, PEER_SOURCE_PEX)
            if ip in self.intro_points:
                # Remove first to put introduction point at front of the deque.
                self.intro_points.remove(ip)
            # Add new introduction point (with up-to-date last_seen)
            self.intro_points.appendleft(ip)

    def introduction_request_callback(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                                      payload: IntroductionRequestPayload | NewIntroductionRequestPayload) -> None:
        """
        Callback for when an introduction request comes in.
        """
        self.process_extra_bytes(peer, payload.extra_bytes)

    def introduction_response_callback(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                                       payload: IntroductionResponsePayload | NewIntroductionResponsePayload) -> None:
        """
        Callback for when an introduction response comes in.
        """
        self.process_extra_bytes(peer, payload.extra_bytes)

    def create_introduction_request(self, socket_address: Address, extra_bytes: bytes = b'', new_style: bool = False,
                                    prefix: bytes | None = None) -> bytes:
        """
        Piggyback introduction points onto introduction requests.
        """
        return super().create_introduction_request(socket_address, self.get_seeder_pks(), new_style)

    def create_introduction_response(self, lan_socket_address: Address, socket_address: Address,  # noqa: PLR0913
                                     identifier: int, introduction: Peer | None = None, extra_bytes: bytes = b'',
                                     prefix: bytes | None = None,
                                     new_style: bool = False) -> bytes:
        """
        Piggyback introduction points onto introduction responses.
        """
        return super().create_introduction_response(lan_socket_address, socket_address, identifier, introduction,
                                                    self.get_seeder_pks(), new_style=new_style)

    def send_ping(self, peer: Peer) -> None:
        """
        Send a ping messages to a peer.
        """
        self.send_introduction_request(peer)

    def get_seeder_pks(self) -> bytes:
        """
        Pack the known seeder public keys (up to 10) as bytes.
        """
        pks = random.sample(self.intro_points_for, min(len(self.intro_points_for), 10))
        return self.serializer.pack('varlenH-list', pks)
