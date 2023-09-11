from typing import cast
from unittest.mock import Mock

from ...dht.provider import DHTCommunityProvider
from ...keyvault.crypto import ECCrypto
from ...messaging.anonymization.tunnel import IntroductionPoint
from ...peer import Peer
from ...util import succeed
from ..base import TestBase


class TestNode(TestBase):
    """
    Tests related to announce and lookup functionality.
    """

    def setUp(self) -> None:
        """

        :return:
        """
        super().setUp()
        self.crypto = ECCrypto()

        self.ip_pk = self.crypto.key_from_public_bin(b'LibNaCLPK:\xc8\xf38};U\xe4\xd5\xf7\xfd\xbc+J!\xbe\xba'
                                                     b'\x81M\xda\xef\xb7\x8c\xacL\x1eZ\x9d\xaf\xaaX+&\xac\xe2'
                                                     b'\xd2\xdd\x86\xa9\x97\xb8T\x9b\x82\xc1>\xa2\r\x11?\xef'
                                                     b'\x137\xf1\xdc!\x7f\x9fW\xe7\x11.\xe2\xc8)')
        self.seeder_pk = self.crypto.key_from_public_bin(b'LibNaCLPK:/N\xc5\xd1#\xd4\xc5\x02\xca\xb4\xa4\xd4vKD'
                                                         b'\xf1"\xf01,\\\xde\x14\x87\xa9\xf6T\x90\xd9\xb0qk\xdbPS'
                                                         b'\xfbqm\xc1,i\xca\x88\x7fm\xe8\\\x0f\xe9\xee\xec\xce\xbeN'
                                                         b'\xdc\x94\xc4\x84\'\x8b\xb8\x8e\x1b\xc4')

        self.intro_point = IntroductionPoint(Peer(self.ip_pk, ('1.2.3.4', 567)),
                                             self.seeder_pk.key_to_bin(), last_seen=0)
        self.info_hash = bytes(range(20))
        self.provider = DHTCommunityProvider(Mock(), self.intro_point.peer.address[1])
        self.dht_value = (b'\x01\x01\x02\x03\x04\x027\x00\x00\x00\x00\x00@\xc8\xf38};U\xe4\xd5\xf7\xfd\xbc+J!\xbe'
                          b'\xba\x81M\xda\xef\xb7\x8c\xacL\x1eZ\x9d\xaf\xaaX+&\xac\xe2\xd2\xdd\x86\xa9\x97\xb8T\x9b'
                          b'\x82\xc1>\xa2\r\x11?\xef\x137\xf1\xdc!\x7f\x9fW\xe7\x11.\xe2\xc8)\x00@/N\xc5\xd1#\xd4\xc5'
                          b'\x02\xca\xb4\xa4\xd4vKD\xf1"\xf01,\\\xde\x14\x87\xa9\xf6T\x90\xd9\xb0qk\xdbPS\xfbqm\xc1,i'
                          b'\xca\x88\x7fm\xe8\\\x0f\xe9\xee\xec\xce\xbeN\xdc\x94\xc4\x84\'\x8b\xb8\x8e\x1b\xc4')

    async def test_announce(self) -> None:
        """
        Check if the DHT value is stored after an announce.
        """
        mock_store_value = cast(Mock, self.provider.dht_community.store_value)
        mock_store_value.return_value = succeed(None)
        await self.provider.announce(self.info_hash, self.intro_point)
        mock_store_value.assert_called_once_with(self.info_hash, self.dht_value)

    async def test_lookup(self) -> None:
        """
        Check if an introduction point is properly created after a lookup.
        """
        self.provider.dht_community.find_values = lambda _: succeed([(self.dht_value, None)])
        info_hash, intro_points = await self.provider.lookup(self.info_hash)
        assert info_hash == self.info_hash
        assert intro_points[0].peer.address == self.intro_point.peer.address
        assert intro_points[0].peer.public_key.key_to_bin() == self.intro_point.peer.public_key.key_to_bin()
        assert intro_points[0].seeder_pk == self.intro_point.seeder_pk
