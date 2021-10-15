import typing

Address = typing.Tuple[str, int]
DataclassPayload = typing.TypeVar('DataclassPayload')

# pylint: disable=unused-import

if typing.TYPE_CHECKING:
    from ipv8.attestation.identity.attestation import Attestation
    from ipv8.attestation.identity.database import Credential
    from ipv8.attestation.identity.manager import PseudonymManager
    from ipv8.attestation.identity.metadata import Metadata
    from ipv8.attestation.identity_formats import IdentityAlgorithm
    from ipv8.attestation.tokentree.token import Token
    from ipv8.attestation.wallet.community import AttestationCommunity
    from ipv8.community import Community
    from ipv8.configuration import ConfigBuilder
    from ipv8.database import Database
    from ipv8.keyvault.keys import Key, PrivateKey, PublicKey
    from ipv8.messaging.interfaces.endpoint import Endpoint
    from ipv8.messaging.serialization import Payload
    from ipv8.overlay import Overlay
    from ipv8.peer import Peer
    from ipv8.requestcache import NumberCache
    from ipv8_service import IPv8

    IdentityAlgorithmClass = typing.Type[IdentityAlgorithm]
else:
    Attestation = 'ipv8.attestation.identity.attestation.Attestation'
    AttestationCommunity = 'ipv8.attestation.wallet.community.AttestationCommunity'
    Community = 'ipv8.community.Community'
    ConfigBuilder = 'ipv8.configuration.ConfigBuilder'
    Credential = 'ipv8.attestation.identity.database.Credential'
    Database = 'ipv8.database.Database'
    Endpoint = 'ipv8.messaging.interfaces.endpoint.Endpoint'
    IdentityAlgorithm = 'ipv8.attestation.identity_formats.IdentityAlgorithm'
    IdentityAlgorithmClass = 'ipv8.attestation.identity_formats.IdentityAlgorithm.__class__'
    IPv8 = 'ipv8_service.IPv8'
    Key = 'ipv8.keyvault.keys.Key'
    Metadata = 'ipv8.attestation.identity.metadata.Metadata'
    NumberCache = 'ipv8.requestcache.NumberCache'
    Overlay = 'ipv8.overlay.Overlay'
    Payload = 'ipv8.messaging.serialization.Payload'
    Peer = 'ipv8.peer.Peer'
    PrivateKey = 'ipv8.keyvault.keys.PrivateKey'
    PseudonymManager = 'ipv8.attestation.identity.manager.PseudonymManager'
    PublicKey = 'ipv8.keyvault.keys.PublicKey'
    Token = 'ipv8.attestation.tokentree.token.Token'

AnyPayload = typing.Union[Payload, DataclassPayload]
AnyPayloadType = typing.Union[typing.Type[Payload], typing.Type[DataclassPayload]]
