from __future__ import annotations

import binascii
import json
import logging
import struct
import typing

from ...keyvault.crypto import ECCrypto
from ...keyvault.keys import PrivateKey
from ..tokentree.tree import TokenTree
from .attestation import Attestation
from .database import Credential, IdentityDatabase
from .metadata import Metadata

if typing.TYPE_CHECKING:
    from ...types import PublicKey, Token


class PseudonymManager:
    """
    Object to manage interactions with our own pseudonym or one belonging to someone else.

    Never create one yourself, use `IdentityManager.get_pseudonym()` instead!
    """

    def __init__(self, database: IdentityDatabase,
                 public_key: PublicKey | None = None,
                 private_key: PrivateKey | None = None) -> None:
        """
        Create a new pseudonym manager.
        """
        super().__init__()

        self.database = database

        self.tree = TokenTree(public_key=public_key, private_key=private_key)
        self.credentials = []

        logging.info("Loading public key %s from database", binascii.hexlify(self.public_key.key_to_hash()).decode())
        for token in self.database.get_tokens_for(self.public_key):
            self.tree.elements[token.get_hash()] = token
        self.credentials = self.database.get_credentials_for(self.public_key)

    @property
    def public_key(self) -> PublicKey:
        """
        Get our associated public key.
        """
        return self.tree.public_key

    def add_credential(self, token: Token, metadata: Metadata,
                       attestations: typing.Set[tuple[PublicKey, Attestation]] | None = None) -> Credential | None:
        """
        Add a credential to this pseudonym.

        :returns: the added credential on success, otherwise None
        """
        # If this token belongs to this chain, insert it.
        # Note: if the given metadata is invalid, the token is still inserted!
        if attestations is None:
            attestations = set()
        if self.tree.gather_token(token) is not None:
            self.database.insert_token(self.public_key, token)

            # If the metadata belongs to this token and chain, insert it.
            if metadata.verify(self.public_key) and metadata.token_pointer == token.get_hash():
                self.database.insert_metadata(self.public_key, metadata)

                # Insert all valid attestations to this metadata.
                valid_attestations = set()
                for authority_key, attestation in attestations:
                    if self.add_attestation(authority_key, attestation):
                        valid_attestations.add(attestation)

                out = Credential(metadata, valid_attestations)
                self.credentials.append(out)
                return out
        return None

    def add_attestation(self, public_key: PublicKey, attestation: Attestation) -> bool:
        """
        Add an attestation to this pseudonym.

        :returns: True on success, otherwise False
        """
        if attestation.verify(public_key):
            self.database.insert_attestation(self.public_key, public_key, attestation)
            return True
        return False

    def add_metadata(self, metadata: Metadata) -> bool:
        """
        Add a metadata entry to this pseudonym.

        :returns: True on success, otherwise False
        """
        if metadata.verify(self.public_key):
            self.database.insert_metadata(self.public_key, metadata)
            return True
        return False

    def create_attestation(self, metadata: Metadata, private_key: PrivateKey) -> Attestation:
        """
        Create an attestation for a a metadata entry of this pseudonym.

        Attesting to your own attributes is allowed (but probably not of any added value).
        """
        return Attestation.create(metadata, private_key)

    def create_credential(self,
                          attestation_hash: bytes,
                          metadata_json: dict,
                          after: Metadata | None = None) -> Credential | None:
        """
        Create a credential and add it to this pseudonym.
        """
        preceding = None if after is None else self.tree.elements.get(after.token_pointer, None)
        token = self.tree.add_by_hash(attestation_hash, preceding)
        metadata = Metadata(token.get_hash(), json.dumps(metadata_json).encode(), self.tree.private_key)
        return self.add_credential(token, metadata, set())

    def get_credential(self, metadata: Metadata) -> Credential:
        """
        Return the credential belonging to given metadata.
        """
        return self.database.get_credential_over(metadata)

    def get_credentials(self) -> list[Credential]:
        """
        Get all credentials belonging to this pseudonym.
        """
        return self.database.get_credentials_for(self.public_key)

    def disclose_credentials(self,
                             credentials: typing.Iterable[Credential],
                             attestation_selector: typing.Set[bytes]) -> tuple[bytes, bytes, bytes, bytes]:
        """
        Create a public disclosure for the given credentials and only include attestations from the given serialized
        public keys.

        This method automatically minimizes the amount of shared tokens and metadata.

        Another instance would receive and load these in using the IdentityManager's `substantiate()` method.

        :returns: the serialized metadata, tokens, attestations and authorities.
        """
        return self.create_disclosure({credential.metadata for credential in credentials}, attestation_selector)

    def create_disclosure(self,
                          metadata: typing.Set[Metadata],
                          attestation_selector: typing.Set[bytes]) -> tuple[bytes, bytes, bytes, bytes]:
        """
        Create a public disclosure for the given set of metadata and only include attestations from the given serialized
        public keys.

        This method automatically minimizes the amount of shared tokens and metadata.

        Another instance would receive and load these in using the IdentityManager's `substantiate()` method.

        :returns: the serialized metadata, tokens, attestations and authorities.
        """
        s_metadata = b''
        for md in metadata:
            serialized = md.get_plaintext_signed()
            s_metadata += struct.pack('>I', len(serialized)) + serialized
        attestations = b''
        authorities = b''
        for m in metadata:
            available_attestations = self.database.get_attestations_over(m)
            for attestation in available_attestations:
                if attestation.get_hash() in attestation_selector:
                    attestations += attestation.get_plaintext_signed()
                    authority = self.database.get_authority(attestation)
                    authority_len = len(authority)
                    authorities += struct.pack(">H", authority_len) + authority
        required_token_hashes = {m.token_pointer for m in metadata}
        tokens = set()
        # Keep adding tokens to this disclosure until all metadata is satisfied.
        for required_token_hash in required_token_hashes:
            root_token = self.tree.elements[required_token_hash]  # Throws a KeyError if the hash is unknown.
            # Avoid infinite loops and broken disclosures.
            if not self.tree.verify(root_token):
                msg = "Attempted to create disclosure for undisclosable Token!"
                raise RuntimeError(msg)
            tokens.add(root_token)
            current_token = root_token
            while current_token.previous_token_hash != self.tree.genesis_hash:
                current_token = self.tree.elements[current_token.previous_token_hash]
                tokens.add(current_token)
        return s_metadata, b''.join(token.get_plaintext_signed() for token in tokens), attestations, authorities


class IdentityManager:
    """
    Manager of our own pseudonyms and those of others.
    """

    def __init__(self, database_path: str = ":memory:") -> None:
        """
        Create a new identity manager.
        """
        super().__init__()

        self.database = IdentityDatabase(database_path)
        self.database.open()
        self.pseudonyms: dict[bytes, PseudonymManager] = {}

        self.crypto = ECCrypto()

    def get_pseudonym(self, key: PublicKey | PrivateKey) -> PseudonymManager:
        """
        Get the pseudonym belonging to a given public or private key.
        """
        public_key_material = key.pub().key_to_bin()
        if public_key_material not in self.pseudonyms:
            # Gotcha: PrivateKey is a subclass of PublicKey
            if isinstance(key, PrivateKey):
                self.pseudonyms[public_key_material] = PseudonymManager(self.database, private_key=key)
            else:
                self.pseudonyms[public_key_material] = PseudonymManager(self.database, public_key=key)
        return self.pseudonyms[public_key_material]

    def substantiate(self,
                     public_key: PublicKey,
                     serialized_metadata: bytes,
                     serialized_tokens: bytes,
                     serialized_attestations: bytes,
                     serialized_authorities: bytes) -> tuple[bool, PseudonymManager]:
        """
        Load the serialized form of a pseudonym for a given public key.

        :returns: whether this pseudonym is valid, the newly loaded pseudonym itself
        """
        # Load the tree structure
        pseudonym = self.get_pseudonym(public_key)
        correct = pseudonym.tree.unserialize_public(serialized_tokens)

        # Load the metadata
        metadata_offset = 0
        while metadata_offset < len(serialized_metadata):
            metadata_len, = struct.unpack_from('>I', serialized_metadata, metadata_offset)
            md = Metadata.unserialize(serialized_metadata[metadata_offset + 4:
                                                          metadata_offset + 4 + metadata_len], public_key)
            pseudonym.add_metadata(md)
            metadata_offset += 4 + metadata_len

        # Load the attestations and respective authorities
        attestation_offset = 0
        authority_offset = 0
        while authority_offset < len(serialized_authorities):
            authority_len, = struct.unpack_from('>H', serialized_authorities, authority_offset)
            authority = self.crypto.key_from_public_bin(serialized_authorities[authority_offset + 2:
                                                                               authority_offset + 2 + authority_len])
            authority_offset += 2 + authority_len
            correct &= pseudonym.add_attestation(authority,
                                                 Attestation.unserialize(serialized_attestations, authority,
                                                                         attestation_offset))
            attestation_offset += 32 + authority.get_signature_length()

        return correct, pseudonym
