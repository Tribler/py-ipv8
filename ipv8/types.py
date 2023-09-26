import typing

Address = typing.Tuple[str, int]

# ruff: noqa: F401

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
    from ipv8.dht.community import DHTCommunity
    from ipv8.keyvault.keys import Key, PrivateKey, PublicKey
    from ipv8.messaging.interfaces.endpoint import Endpoint
    from ipv8.messaging.serialization import Payload
    from ipv8.overlay import Overlay
    from ipv8.peer import Peer
    from ipv8.peerdiscovery.network import Network
    from ipv8.requestcache import NumberCache
    from ipv8_service import IPv8
else:
    Attestation = 'ipv8.attestation.identity.attestation.Attestation'
    AttestationCommunity = 'ipv8.attestation.wallet.community.AttestationCommunity'
    Community = 'ipv8.community.Community'
    ConfigBuilder = 'ipv8.configuration.ConfigBuilder'
    Credential = 'ipv8.attestation.identity.database.Credential'
    Database = 'ipv8.database.Database'
    DHTCommunity = 'ipv8.dht.community.DHTCommunity'
    Endpoint = 'ipv8.messaging.interfaces.endpoint.Endpoint'
    IdentityAlgorithm = 'ipv8.attestation.identity_formats.IdentityAlgorithm'
    IPv8 = 'ipv8_service.IPv8'
    Key = 'ipv8.keyvault.keys.Key'
    Metadata = 'ipv8.attestation.identity.metadata.Metadata'
    Network = 'ipv8.peerdiscovery.network.Network'
    NumberCache = 'ipv8.requestcache.NumberCache'
    Overlay = 'ipv8.overlay.Overlay'
    Payload = 'ipv8.messaging.serialization.Payload'
    Peer = 'ipv8.peer.Peer'
    PrivateKey = 'ipv8.keyvault.keys.PrivateKey'
    PseudonymManager = 'ipv8.attestation.identity.manager.PseudonymManager'
    PublicKey = 'ipv8.keyvault.keys.PublicKey'
    Token = 'ipv8.attestation.tokentree.token.Token'


MessageHandlerFunction = typing.Union[typing.Callable[[Overlay, Address, bytes],
                                                      None],
                                      typing.Callable[[Address, bytes],
                                                      None],
                                      typing.Callable[[Overlay, Address, bytes],
                                                      typing.Coroutine[typing.Any, typing.Any, None]],
                                      typing.Callable[[Address, bytes],
                                                      typing.Coroutine[typing.Any, typing.Any, None]]]

LazyWrappedHandler = typing.Union[typing.Callable[..., None],
                                  typing.Callable[..., typing.Coroutine[typing.Any, typing.Any, None]]]
"""
 ..
 typing.Union[
    typing.Callable[[Overlay, Peer, *list[Payload]], None],
    typing.Callable[[Peer, *list[Payload]], None],
    typing.Callable[[Overlay, Peer, *list[Payload]],
                    typing.Coroutine[typing.Any, typing.Any, None]],
    typing.Callable[[Peer, *list[Payload]],
                    typing.Coroutine[typing.Any, typing.Any, None]]
 ]"""

LazyWrappedUnsignedHandler = typing.Union[typing.Callable[..., None],
                                          typing.Callable[..., typing.Coroutine[typing.Any, typing.Any, None]]]
"""
 ..
 typing.Union[
    typing.Callable[[Overlay, Address, *list[Payload]], None],
    typing.Callable[[Address, *list[Payload]], None],
    typing.Callable[[Overlay, Address, *list[Payload]],
                    typing.Coroutine[typing.Any, typing.Any, None]],
    typing.Callable[[Address, *list[Payload]],
                    typing.Coroutine[typing.Any, typing.Any, None]]
 ]"""

LazyWrappedWDataHandler = typing.Union[typing.Callable[..., None],
                                       typing.Callable[..., typing.Coroutine[typing.Any, typing.Any, None]]]
"""
 ..
 typing.Union[
    typing.Callable[[Overlay, Peer, *list[Payload], KwArg(bytes, "data")], None],
    typing.Callable[[Peer, *list[Payload], KwArg(bytes, "data")], None],
    typing.Callable[[Overlay, Peer, *list[Payload], KwArg(bytes, "data")],
                    typing.Coroutine[typing.Any, typing.Any, None]],
    typing.Callable[[Peer, *list[Payload], KwArg(bytes, "data")],
                    typing.Coroutine[typing.Any, typing.Any, None]]
 ]"""

LazyWrappedWDataUnsignedHandler = typing.Union[typing.Callable[..., None],
                                               typing.Callable[..., typing.Coroutine[typing.Any, typing.Any, None]]]
"""
 ..
 typing.Union[
    typing.Callable[[Overlay, Address, *list[Payload], KwArg(bytes, "data")], None],
    typing.Callable[[Address, *list[Payload], KwArg(bytes, "data")], None],
    typing.Callable[[Overlay, Address, *list[Payload], KwArg(bytes, "data")],
                    typing.Coroutine[typing.Any, typing.Any, None]],
    typing.Callable[[Address, *list[Payload], KwArg(bytes, "data")],
                    typing.Coroutine[typing.Any, typing.Any, None]]
 ]"""
