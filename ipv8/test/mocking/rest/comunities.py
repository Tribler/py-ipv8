from ....attestation.identity.community import IdentityCommunity
from ....attestation.wallet.community import AttestationCommunity
from ....keyvault.crypto import ECCrypto
from ....peer import Peer


class TestAttestationCommunity(AttestationCommunity):
    master_peer = Peer(ECCrypto().generate_key(u'high'))


class TestIdentityCommunity(IdentityCommunity):
    master_peer = Peer(ECCrypto().generate_key(u'high'))
