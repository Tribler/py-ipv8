import random 

from collections import deque

from ...community import Community
from ...messaging.deprecated.encoding import encode, decode
from ...messaging.anonymization.tunnel import IntroductionPoint

MAX_INTRODUCTION_POINTS = 20


class PexMasterPeer(object):
    def __init__(self, info_hash):
        self.mid = info_hash


class PexCommunity(Community):
    def __init__(self, *args, **kwargs):
        self.master_peer = PexMasterPeer(kwargs.pop('info_hash'))
        super(PexCommunity, self).__init__(*args, **kwargs)

        self.intro_points = deque(maxlen=100)
        self.intro_points_for = []
        
    def get_intro_points(self):
        """
        Get a list of the most recent introduction points that were discovered using PexCommunity.
        :return : list of IntroductionPoint objects
        """
        return list(self.intro_points) + \
               [IntroductionPoint(self.my_peer, seeder_pk) for seeder_pk in self.intro_points_for]

    def start_announce(self, seeder_pk):
        """
        Start announcing yourself as an introduction point for a certain seeder.
        :param seeder_pk: public key of the seeder (in binary format)
        """
        self.intro_points_for.append(seeder_pk)

    def stop_announce(self, seeder_pk):
        """
        Stop announcing yourself as an introduction point for a certain seeder.
        :param seeder_pk: public key of the seeder (in binary format)
        """
        self.intro_points_for.remove(seeder_pk)

    @property
    def done(self):
        return bool(self.intro_points_for)

    def process_extra_bytes(self, peer, extra_bytes):
        for seeder_pk in decode(extra_bytes)[1]:
            ip = IntroductionPoint(peer, seeder_pk)
            if ip in self.intro_points:
                # Remove first to put introduction point at front of the deque.
                self.intro_points.remove(ip)
            # Add new introduction point (with up-to-date last_seen)
            self.intro_points.append(ip)

    def introduction_request_callback(self, peer, dist, payload):
        self.process_extra_bytes(peer, payload.extra_bytes)

    def introduction_response_callback(self, peer, dist, payload):
        self.process_extra_bytes(peer, payload.extra_bytes)

    def create_introduction_request(self, socket_address, extra_bytes=b''):
        extra_bytes = encode(random.sample(self.intro_points_for, min(len(self.intro_points_for), 10)))
        return super(PexCommunity, self).create_introduction_request(socket_address, extra_bytes)

    def create_introduction_response(self, lan_socket_address, socket_address, identifier,
                                     introduction=None, extra_bytes=b''):
        extra_bytes = encode(random.sample(self.intro_points_for, min(len(self.intro_points_for), 10)))
        return super(PexCommunity, self).create_introduction_response(lan_socket_address, socket_address,
                                                                      identifier, introduction, extra_bytes)