import random
import time
from collections import deque

from ...community import Community
from ...messaging.anonymization.tunnel import IntroductionPoint, PEER_SOURCE_PEX
from ...peer import Peer

PEX_VERSION = 1


class PexCommunity(Community):
    def __init__(self, *args, **kwargs):
        infohash = kwargs.pop('info_hash')
        self.community_id = (int.from_bytes(infohash, 'big') + PEX_VERSION).to_bytes(20, 'big')
        self._prefix = b'\x00' + self.version + self.community_id
        super().__init__(*args, **kwargs)

        self.intro_points = deque(maxlen=20)
        self.intro_points_for = []

    def get_intro_points(self):
        """
        Get a list of the most recent introduction points that were discovered using PexCommunity.
        :return : list of IntroductionPoint objects
        """

        # Remove old introduction points
        now = time.time()
        while self.intro_points and self.intro_points[-1].last_seen + 300 < now:
            self.intro_points.pop()

        my_peer = Peer(self.my_peer.key, self.my_estimated_wan)
        return list(self.intro_points) + [IntroductionPoint(my_peer, seeder_pk, PEER_SOURCE_PEX)
                                          for seeder_pk in self.intro_points_for]

    def start_announce(self, seeder_pk):
        """
        Start announcing yourself as an introduction point for a certain seeder.
        :param seeder_pk: public key of the seeder (in binary format)
        """
        if seeder_pk not in self.intro_points_for:
            self.intro_points_for.append(seeder_pk)

    def stop_announce(self, seeder_pk):
        """
        Stop announcing yourself as an introduction point for a certain seeder.
        :param seeder_pk: public key of the seeder (in binary format)
        """
        if seeder_pk in self.intro_points_for:
            self.intro_points_for.remove(seeder_pk)

    @property
    def done(self):
        return not bool(self.intro_points_for)

    def process_extra_bytes(self, peer, extra_bytes):
        if not extra_bytes:
            return

        for seeder_pk in self.serializer.unpack('varlenH-list', extra_bytes)[0]:
            ip = IntroductionPoint(peer, seeder_pk, PEER_SOURCE_PEX)
            if ip in self.intro_points:
                # Remove first to put introduction point at front of the deque.
                self.intro_points.remove(ip)
            # Add new introduction point (with up-to-date last_seen)
            self.intro_points.appendleft(ip)

    def introduction_request_callback(self, peer, dist, payload):
        self.process_extra_bytes(peer, payload.extra_bytes)

    def introduction_response_callback(self, peer, dist, payload):
        self.process_extra_bytes(peer, payload.extra_bytes)

    def create_introduction_request(self, socket_address, extra_bytes=b'', new_style=False):
        return super().create_introduction_request(socket_address, self.get_seeder_pks(), new_style)

    def create_introduction_response(self, lan_socket_address, socket_address, identifier,
                                     introduction=None, extra_bytes=b'', prefix=None, new_style=False):
        return super().create_introduction_response(lan_socket_address, socket_address, identifier, introduction,
                                                    self.get_seeder_pks(), new_style=new_style)

    def send_ping(self, peer):
        self.send_introduction_request(peer)

    def get_seeder_pks(self):
        pks = random.sample(self.intro_points_for, min(len(self.intro_points_for), 10))
        return self.serializer.pack('varlenH-list', pks)
