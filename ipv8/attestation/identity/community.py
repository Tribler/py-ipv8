from __future__ import annotations

import json
import os
from binascii import hexlify, unhexlify
from time import time
from typing import TYPE_CHECKING, cast

from ...bootstrapping.dispersy.bootstrapper import DispersyBootstrapper
from ...community import Community, CommunitySettings
from ...configuration import DISPERSY_BOOTSTRAPPER
from ...keyvault.keys import PrivateKey, PublicKey
from ...lazy_community import lazy_wrapper
from ...peer import Peer
from ...peerdiscovery.discovery import RandomWalk
from ...peerdiscovery.network import Network
from .attestation import Attestation
from .manager import IdentityManager
from .payload import AttestPayload, DiclosePayload, MissingResponsePayload, RequestMissingPayload

if TYPE_CHECKING:
    from ...types import Credential, Endpoint, IPv8, Metadata, PseudonymManager, Token

SAFE_UDP_PACKET_LENGTH = 1296


class IdentitySettings(CommunitySettings):
    """
    Settings for the Identity community.
    """

    identity_manager: IdentityManager | None = None

    working_directory: str = "."


class IdentityCommunity(Community):
    """
    Community for business logic surrounding identities.

    Actual identity information goes through the wallet.
    """

    community_id = unhexlify('d5889074c1e4c50423cdb6e9307ee0ca5695ead7')
    settings_class = IdentitySettings

    def __init__(self, settings: IdentitySettings) -> None:
        """
        Create a new identity management overlay.
        """
        if not hasattr(settings, "network"):
            settings.network = Network()
        super().__init__(settings)
        if settings.identity_manager is None:
            dbpath = (":memory:" if settings.working_directory == ":memory:"
                      else os.path.join(settings.working_directory, "sqlite", "identity.db"))
            settings.identity_manager = IdentityManager(database_path=dbpath)

        # Dict of hash -> (attribute_name, date, public_key)
        self.known_attestation_hashes: dict[bytes, tuple[str, float, bytes, dict[str, str] | None]] = {}

        self.identity_manager = settings.identity_manager
        self.pseudonym_manager = settings.identity_manager.get_pseudonym(cast(PrivateKey, self.my_peer.key))

        # We assume other people try to cheat us with trees.
        # We don't attack ourselves though and just maintain a chain of attributes per pseudonym.
        self.token_chain: list[Token] = []
        self.metadata_chain = []
        self.attestation_chain = []
        self.permissions: dict[Peer, int] = {}  # Map of peer to highest index

        # Pick the longest chain in case of bugs or malicious behavior.. hello Bitcoin.
        for token in self.pseudonym_manager.tree.elements.values():
            chain = self.pseudonym_manager.tree.get_root_path(token)
            if len(chain) > len(self.token_chain):
                self.token_chain = chain
        for credential in self.pseudonym_manager.get_credentials():
            for token in self.token_chain:
                if credential.metadata.token_pointer == token.get_hash():
                    self.metadata_chain.append(credential.metadata)
                    self.attestation_chain.append(credential.attestations)
                    break

        # Register messages
        self.add_message_handler(DiclosePayload, self.on_disclosure)
        self.add_message_handler(AttestPayload, self.on_attest)
        self.add_message_handler(RequestMissingPayload, self.on_request_missing)
        self.add_message_handler(MissingResponsePayload, self.on_missing_response)

    def pad_hash(self, attribute_hash: bytes) -> bytes:
        """
        Pad an old-style SHA-1 hash into the new 32 byte SHA3-256 space.
        """
        self.logger.debug("Padding deprecated SHA-1 hash to 32 bytes, use SHA3-256 instead!")
        return b'SHA-1\x00\x00\x00\x00\x00\x00\x00' + attribute_hash

    def add_known_hash(self,
                       attribute_hash: bytes,
                       name: str,
                       public_key: bytes,
                       metadata: dict[str, str] | None = None) -> None:
        """
        We know about this hash+peer combination. Thus we can handle sign requests for it.
        """
        if len(attribute_hash) == 20:
            attribute_hash = self.pad_hash(attribute_hash)
        self.known_attestation_hashes[attribute_hash] = (name, time(), public_key, metadata)

    def get_attestation_by_hash(self, attribute_hash: bytes) -> Metadata | None:
        """
        Get the Metadata object for a particular attribute hash, if it exists.
        """
        if len(attribute_hash) == 20:
            attribute_hash = self.pad_hash(attribute_hash)
        for credential in self.pseudonym_manager.get_credentials():
            token = self.pseudonym_manager.tree.elements[credential.metadata.token_pointer]
            if token.content_hash == attribute_hash:
                return credential.metadata
        return None

    def should_sign(self,  # noqa: PLR0911
                    pseudonym: PseudonymManager,
                    metadata: Metadata) -> bool:
        """
        Has the user asked us to sign for some metadata and is it still valid?
        """
        transaction = json.loads(metadata.serialized_json_dict)
        requested_keys = set(transaction.keys())
        if metadata.token_pointer not in pseudonym.tree.elements:
            return False
        attribute_hash = pseudonym.tree.elements[metadata.token_pointer].content_hash
        if "name" not in requested_keys or "date" not in requested_keys or "schema" not in requested_keys:
            self.logger.debug("Not signing %s, it doesn't include the required fields!", str(metadata))
            return False
        if attribute_hash not in self.known_attestation_hashes:
            self.logger.debug("Not signing %s, it doesn't point to known content!", str(metadata))
            return False
        if pseudonym.public_key.key_to_bin() != self.known_attestation_hashes[attribute_hash][2]:
            self.logger.debug("Not signing %s, attribute doesn't belong to key!", str(metadata))
            return False
        # Refuse to sign blocks older than 5 minutes
        if time() > self.known_attestation_hashes[attribute_hash][1] + 300:
            self.logger.debug("Not signing %s, timed out!", str(metadata))
            return False
        if transaction['name'] != self.known_attestation_hashes[attribute_hash][0]:
            self.logger.debug("Not signing %s, name does not match!", str(metadata))
            return False
        if (self.known_attestation_hashes[attribute_hash][3] is not None
                and ({k: v for k, v in transaction.items() if k not in ["name", "date", "schema"]}
                     != self.known_attestation_hashes[attribute_hash][3])):
            self.logger.debug("Not signing %s, metadata does not match!", str(metadata))
            return False
        for attestation in pseudonym.database.get_attestations_over(metadata):
            if any(authority == self.my_peer.public_key.key_to_bin()
                   for authority in pseudonym.database.get_authority(attestation)):
                self.logger.debug("Not signing %s, already attested!", str(metadata))
                return False
        return True

    def _fit_disclosure(self, disclosure: tuple[bytes, bytes, bytes, bytes]) -> tuple[bytes, bytes, bytes, bytes]:
        """
        Fit a disclosure (metadata, tokens, attestations and authorities) to a UDP packet.

        This comes down to stripping tokens until the serialization fits in a UDP packet, as tokens can be shown
        to be missing from a disclosure and will be retrieved on demand
        """
        token_size = 64 + self.crypto.get_signature_length(cast(PublicKey, self.my_peer.key))
        metadata, tokens, attestations, authorities = disclosure
        meta_len = len(metadata) + len(attestations) + len(authorities)
        if meta_len + len(tokens) > SAFE_UDP_PACKET_LENGTH:
            packet_space = SAFE_UDP_PACKET_LENGTH - meta_len
            if packet_space < 0:
                self.logger.warning("Attempting to disclose with packet of length %d, hoping for the best!", meta_len)
            packet_space = max(0, packet_space)
            trim_len = packet_space // token_size
            tokens = tokens[-trim_len * token_size:]
        return metadata, tokens, attestations, authorities

    def _received_disclosure_for_attest(self,
                                        peer: Peer,
                                        disclosure: tuple[bytes, bytes, bytes, bytes]) -> None:
        """
        Attempt to insert a disclosure into our database and request more if we are still missing tokens.
        """
        solicited = any(t[2] == peer.public_key.key_to_bin() for t in self.known_attestation_hashes.values())
        if solicited:
            correct, pseudonym = self.identity_manager.substantiate(peer.public_key, *disclosure)
            required_attributes = [attribute_hash for attribute_hash in self.known_attestation_hashes
                                   if self.known_attestation_hashes[attribute_hash][2] == peer.public_key.key_to_bin()]
            known_attributes = [token.content_hash for token in pseudonym.tree.elements.values()]
            if correct and any(attribute_hash in known_attributes for attribute_hash in required_attributes):
                for credential in pseudonym.get_credentials():
                    if self.should_sign(pseudonym, credential.metadata):
                        self.logger.info("Attesting to %s", str(credential.metadata))
                        attestation = pseudonym.create_attestation(credential.metadata,
                                                                   cast(PrivateKey, self.my_peer.key))
                        pseudonym.add_attestation(self.my_peer.public_key, attestation)
                        self.ez_send(peer, AttestPayload(attestation.get_plaintext_signed()))
            for attribute_hash in required_attributes:
                if attribute_hash not in known_attributes:
                    self.logger.info("Missing information for attestation %s, requesting more!",
                                     hexlify(attribute_hash).decode())
                    self.ez_send(peer, RequestMissingPayload(len(pseudonym.tree.elements)))
        else:
            self.logger.warning("Received unsolicited disclosure from %s, dropping!", str(peer))

    def request_attestation_advertisement(self,
                                          peer: Peer,
                                          attribute_hash: bytes,
                                          name: str,
                                          block_type: str = "id_metadata",
                                          metadata: dict | None = None) -> None:
        """
        Request a peer to sign for our attestation advertisement.

        :param peer: the attestor of our block
        :param attribute_hash: the hash of the attestation
        :param name: the name of the attribute (metadata)
        :param block_type: the type of block (from identity_foromats.py)
        :param metadata: custom additional metadata
        """
        credential = self.self_advertise(attribute_hash, name, block_type, metadata)
        if credential is None:
            self.logger.exception("Failed to create credential %s: aborting!", name)
        else:
            self.permissions[peer] = len(self.token_chain)
            disclosure = self.pseudonym_manager.disclose_credentials([credential], set())
            self.ez_send(peer, DiclosePayload(*self._fit_disclosure(disclosure)))

    def self_advertise(self,
                       attribute_hash: bytes,
                       name: str,
                       block_type: str = "id_metadata",
                       metadata: dict | None = None) -> Credential | None:
        """
        Self-sign an attribute.

        :param attribute_hash: the hash of the attestation
        :param name: the name of the attribute (metadata)
        :param block_type: the type of block (from identity_formats.py)
        :param metadata: custom additional metadata
        """
        if len(attribute_hash) == 20:
            attribute_hash = self.pad_hash(attribute_hash)

        # Construct metadata fields
        extended_metadata = {
            "name": name,
            "schema": block_type,
            "date": time()
        }
        if metadata:
            extended_metadata.update(metadata)

        # Create credential
        credential = self.pseudonym_manager.create_credential(attribute_hash, extended_metadata,
                                                              self.metadata_chain[-1] if self.metadata_chain else None)

        if credential is None:
            return None

        # Construct chain data view
        self.attestation_chain.append(credential.attestations)
        self.metadata_chain.append(credential.metadata)
        self.token_chain.append(self.pseudonym_manager.tree.elements[credential.metadata.token_pointer])

        return credential

    @lazy_wrapper(DiclosePayload)
    def on_disclosure(self, peer: Peer, disclosure: DiclosePayload) -> None:
        """
        Someone disclosed their attributes to us.
        Attempt to insert them into our database and check if we are still missing some.
        """
        self._received_disclosure_for_attest(peer, (disclosure.metadata, disclosure.tokens, disclosure.attestations,
                                                    disclosure.authorities))

    @lazy_wrapper(AttestPayload)
    def on_attest(self, peer: Peer, payload: AttestPayload) -> None:
        """
        Someone made an attestation for us, try to insert it into our database.
        """
        attestation = Attestation.unserialize(payload.attestation, peer.public_key)
        if self.pseudonym_manager.add_attestation(peer.public_key, attestation):
            self.logger.info("Received attestation from %s!", str(peer))
        else:
            self.logger.warning("Received invalid attestation from %s!", str(peer))

    @lazy_wrapper(RequestMissingPayload)
    def on_request_missing(self, peer: Peer, request: RequestMissingPayload) -> None:
        """
        Someone requested tokens from us. If they are permitted to see them, send them over.

        Note that tokens do not have indices publicly, so instead of sending missing tokens one at a time,
        we send a range, starting from the lowest index that is missing.
        """
        out = b''
        permitted = self.token_chain[:self.permissions.get(peer, 0)]
        for index, token in enumerate(permitted):
            if index >= request.known:
                serialized = token.get_plaintext_signed()
                if len(out) + len(serialized) > SAFE_UDP_PACKET_LENGTH:
                    break
                out += serialized
        self.ez_send(peer, MissingResponsePayload(out))

    @lazy_wrapper(MissingResponsePayload)
    def on_missing_response(self, peer: Peer, response: MissingResponsePayload) -> None:
        """
        We received tokens, attempt to insert them into our database and check if we are still missing some.
        """
        self._received_disclosure_for_attest(peer, (b'', response.tokens, b'', b''))


async def create_community(private_key: PrivateKey, ipv8: IPv8, identity_manager: IdentityManager,  # noqa: PLR0913
                           endpoint: Endpoint | None = None, working_directory: str | None = None,
                           anonymize: bool = True,
                           rendezvous_token: bytes | None = None) -> IdentityCommunity:
    """
    Create an anonymized runtime overlay to meet other peers for identity business logic.
    """
    my_peer = Peer(private_key)
    if endpoint is None:
        endpoint = await ipv8.produce_anonymized_endpoint()
    working_directory_str: str = (working_directory if working_directory
                                  else ipv8.configuration.get('working_directory'))
    overlay_cls = IdentityCommunity
    if rendezvous_token is not None:
        token_str = hexlify(rendezvous_token).decode()
        rendezvous_id = bytes(b ^ rendezvous_token[i] if i < len(rendezvous_token) else b
                              for i, b in enumerate(IdentityCommunity.community_id))
        overlay_cls = type(f"IdentityCommunity-{token_str}", (IdentityCommunity, ), {  # type:ignore[assignment]
            'community_id': rendezvous_id
        })
    community = overlay_cls(IdentitySettings(my_peer=my_peer, endpoint=endpoint, identity_manager=identity_manager,
                                             working_directory=working_directory_str, anonymize=anonymize))
    community.bootstrappers = [DispersyBootstrapper(**DISPERSY_BOOTSTRAPPER['init'])]
    ipv8.add_strategy(community, RandomWalk(community), -1)
    return community
