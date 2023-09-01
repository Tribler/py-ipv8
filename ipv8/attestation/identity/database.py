from __future__ import annotations

import typing

from ...database import Database
from ..tokentree.token import Token
from .attestation import Attestation
from .metadata import Metadata

if typing.TYPE_CHECKING:
    from ...types import PublicKey


class Credential:
    """
    Cache for Metadata <- [Attestation] mappings.
    """

    def __init__(self, metadata: Metadata, attestations: typing.Set[Attestation]) -> None:
        """
        Create a new credential.
        """
        self.metadata = metadata
        self.attestations = attestations


def to_list(obj: typing.Any | None) -> list:  # noqa: ANN401
    """
    If no results are found in the database, the cursor will return None.
    This function always returns a list.
    """
    return [] if obj is None else list(obj)


class IdentityDatabase(Database):
    """
    Database to store identity layer data.

    This database stores: meta information of different pseudonyms, both ours and those of others.
    This database does not store: commitments and schemes for proving knowledge of data.
    """

    LATEST_DB_VERSION = 1

    def insert_token(self, public_key: PublicKey, token: Token) -> None:
        """
        Inject a Token belonging to a certain public key into this database.
        """
        previous_token_hash, signature, content_hash, content = token.to_database_tuple()
        self.execute("INSERT OR IGNORE INTO Tokens "
                     "(public_key, previous_token_hash, signature, content_hash, content) "
                     "VALUES(?,?,?,?,?)",
                     (public_key.key_to_bin(), previous_token_hash, signature, content_hash, content))
        self.commit()

    def insert_metadata(self, public_key: PublicKey, metadata: Metadata) -> None:
        """
        Inject Metadata belonging to a certain public key into this database.
        """
        token_pointer, signature, serialized_json_dict = metadata.to_database_tuple()
        self.execute("INSERT OR IGNORE INTO Metadata "
                     "(public_key, token_pointer, signature, serialized_json_dict) "
                     "VALUES(?,?,?,?)",
                     (public_key.key_to_bin(), token_pointer, signature, serialized_json_dict))
        self.commit()

    def insert_attestation(self, public_key: PublicKey, authority_key: PublicKey, attestation: Attestation) -> None:
        """
        Inject an Attestation made by some authority for a certain public key into this database.
        """
        metadata_pointer, signature = attestation.to_database_tuple()
        self.execute("INSERT OR IGNORE INTO Attestations "
                     "(public_key, authority_key, metadata_pointer, signature) "
                     "VALUES(?,?,?,?)",
                     (public_key.key_to_bin(), authority_key.key_to_bin(), metadata_pointer, signature))
        self.commit()

    def get_tokens_for(self, public_key: PublicKey) -> typing.Set[Token]:
        """
        Get all tokens in the tree of a certain public key.
        """
        tokens = to_list(self.execute("SELECT previous_token_hash, signature, content_hash, content "
                                      "FROM Tokens WHERE public_key = ?", (public_key.key_to_bin(),),
                                      fetch_all=True))
        return {Token.from_database_tuple(*token) for token in tokens}

    def get_metadata_for(self, public_key: PublicKey) -> typing.Set[Metadata]:
        """
        Get all known metadata for a certain public key.
        """
        metadata = to_list(self.execute("SELECT token_pointer, signature, serialized_json_dict "
                                        "FROM Metadata WHERE public_key = ?", (public_key.key_to_bin(),),
                                        fetch_all=True))
        return {Metadata.from_database_tuple(*metadato) for metadato in metadata}

    def get_attestations_for(self, public_key: PublicKey) -> typing.Set[Attestation]:
        """
        Get all known attestations (made by others) for a certain public key.
        """
        attestations = to_list(self.execute("SELECT metadata_pointer, signature FROM Attestations WHERE public_key = ?",
                                            (public_key.key_to_bin(),), fetch_all=True))
        return {Attestation.from_database_tuple(*attestation) for attestation in attestations}

    def get_attestations_by(self, public_key: PublicKey) -> typing.Set[Attestation]:
        """
        Get all attestations made by a certain public key (for others).

        This is the signing authority.
        """
        attestations = to_list(self.execute("SELECT metadata_pointer, signature "
                                            "FROM Attestations WHERE authority_key = ?",
                                            (public_key.key_to_bin(),), fetch_all=True))
        return {Attestation.from_database_tuple(*attestation) for attestation in attestations}

    def get_attestations_over(self, metadata: Metadata) -> typing.Set[Attestation]:
        """
        Get all known attestations for given metadata.
        """
        attestations = to_list(self.execute("SELECT metadata_pointer, signature FROM Attestations "
                                            "WHERE metadata_pointer = ?",
                                            (metadata.get_hash(),), fetch_all=True))
        return {Attestation.from_database_tuple(*attestation) for attestation in attestations}

    def get_authority(self, attestation: Attestation) -> bytes:
        """
        Retrieve the authority that created a certain attestation.
        """
        return next(typing.cast(typing.Iterator[bytes], self.execute("SELECT authority_key FROM Attestations "
                                                                     "WHERE signature = ?", (attestation.signature,),
                                                                     fetch_all=False)))

    def get_credential_over(self, metadata: Metadata) -> Credential:
        """
        Collect all attestations for the given metadata, forming a credential.
        """
        return Credential(metadata, self.get_attestations_over(metadata))

    def get_credentials_for(self, public_key: PublicKey) -> list[Credential]:
        """
        Get all credentials for a given public key.
        """
        return [Credential(metadata, self.get_attestations_over(metadata))
                for metadata in self.get_metadata_for(public_key)]

    def get_known_identities(self) -> list[bytes]:
        """
        List the public keys of all known identity owners.
        """
        # These are single item tuples
        return [result[0] for result in typing.cast(typing.Iterator[typing.List[bytes]],
                                                    self.execute("SELECT public_key FROM Tokens", fetch_all=True))]

    def get_schema(self, version: int) -> str:
        """
        Return the schema for the database.
        """
        schema = """
                 CREATE TABLE IF NOT EXISTS Tokens(
                 public_key BLOB,
                 previous_token_hash BLOB,
                 signature BLOB,
                 content_hash BLOB,
                 content LONGBLOB,

                 PRIMARY KEY (public_key, previous_token_hash, content_hash)
                 );

                 CREATE TABLE IF NOT EXISTS Metadata(
                 public_key BLOB,
                 token_pointer BLOB,
                 signature BLOB,
                 serialized_json_dict LONGBLOB,

                 PRIMARY KEY (public_key, token_pointer)
                 );

                 CREATE TABLE IF NOT EXISTS Attestations(
                 public_key BLOB,
                 authority_key BLOB,
                 metadata_pointer BLOB,
                 signature BLOB,

                 PRIMARY KEY (public_key, metadata_pointer)
                 );

                 CREATE TABLE IF NOT EXISTS option(key TEXT PRIMARY KEY, value BLOB);
                 DELETE FROM option WHERE key = 'database_version';
                 INSERT INTO option(key, value) VALUES('database_version', '%s');
                 """
        return schema % str(self.LATEST_DB_VERSION)

    def check_database(self, database_version: bytes) -> int:
        """
        Check if we need to upgrade.
        """
        assert database_version.isdigit()
        assert int(database_version) >= 0
        database_version_num = int(database_version) or self.LATEST_DB_VERSION

        # This is where an existing schema would be upgraded.
        # As no changes have been made, there is nothing to upgrade.

        self.executescript(self.get_schema(database_version_num))
        self.commit()

        return self.LATEST_DB_VERSION
