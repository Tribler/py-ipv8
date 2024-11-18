from __future__ import annotations

import os
from collections.abc import Iterator, Sequence
from typing import TYPE_CHECKING, Any, cast

from typing_extensions import Protocol

from ...database import Database

if TYPE_CHECKING:
    from collections.abc import Mapping

    from _typeshed import SupportsLenAndGetItem

    from ..identity_formats import Attestation

DATABASE_DIRECTORY = os.path.join("sqlite")


class SecretKeyProtocol(Protocol):
    """
    Protocol to detect key-like objects.
    """

    def public_key(self) -> Any:  # noqa: ANN401
        """
        Get the associated public key.
        """

    def serialize(self) -> bytes:
        """
        Serialize to bytes.
        """


class AttestationsDB(Database):
    """
    Database to store attestations.
    """

    LATEST_DB_VERSION = 2

    def __init__(self, working_directory: str, db_name: str) -> None:
        """
        Sets up the persistence layer ready for use.
        :param working_directory: Path to the working directory
        that will contain the the db at working directory/DATABASE_PATH
        :param db_name: The name of the database.
        """
        if working_directory != ":memory:":
            db_path = os.path.join(working_directory, os.path.join(DATABASE_DIRECTORY, f"{db_name}.db"))
        else:
            db_path = working_directory
        super().__init__(db_path)
        self.db_name = db_name
        self.open()

    def _get(self, query: str, params: SupportsLenAndGetItem | Mapping[str, Any]) -> list[bytes]:
        return list(cast(Iterator[bytes], self.execute(query, params, fetch_all=False)))

    def get_attestation_by_hash(self, attestation_hash: bytes) -> list[bytes]:
        """
        Retrieve a serialized attestation by hash.
        """
        return self._get(f"SELECT blob FROM {self.db_name} WHERE hash = ?",   # noqa: S608
                         (attestation_hash,))

    def get_all(self) -> list[Sequence[bytes]]:
        """
        Get all serialized attestations we know of.
        """
        return list(cast(list[Sequence[bytes]], self.execute(f"SELECT * FROM {self.db_name}",  # noqa: S608
                                                             (), fetch_all=True)))

    def insert_attestation(self, attestation: Attestation, attestation_hash: bytes, secret_key: SecretKeyProtocol,
                           id_format: str) -> None:
        """
        Insert an attestation into the database.
        """
        blob = attestation.serialize_private(secret_key.public_key())
        self.execute(
            f"INSERT INTO {self.db_name} (hash, blob, key, id_format) VALUES(?,?,?,?)",
            (attestation_hash, blob, secret_key.serialize(),
             id_format.encode('utf-8')))
        self.commit()

    def get_schema(self, version: int) -> str:
        """
        Return the schema for the database.
        """
        schema = ""
        if version == 1:
            schema = f"""
                     CREATE TABLE IF NOT EXISTS {self.db_name}(
                     hash                 BLOB,
                     blob                 LONGBLOB,
                     key                  MEDIUMBLOB

                     PRIMARY KEY (hash)
                     );
                     """
        elif version == 2:
            schema = f"""
                     CREATE TABLE IF NOT EXISTS {self.db_name}(
                     hash                 BLOB,
                     blob                 LONGBLOB,
                     key                  MEDIUMBLOB,
                     id_format            TINYTEXT,

                     PRIMARY KEY (hash)
                     );
                     """
        schema += ("CREATE TABLE IF NOT EXISTS option(key TEXT PRIMARY KEY, value BLOB);\n"
                   "DELETE FROM option WHERE key = 'database_version';\n"
                   f"INSERT INTO option(key, value) VALUES('database_version', '{self.LATEST_DB_VERSION!s}');\n")
        return schema

    def get_upgrade_script(self, current_version: int) -> str | None:
        """
        Return the upgrade script for a specific version.
        :param current_version: the version of the script to return.
        """
        if current_version == 1:
            return (f"ALTER TABLE {self.db_name}\n"
                    "ADD id_format TINYTEXT;\n\n"
                    f"UPDATE {self.db_name} SET id_format='id_metadata';\n")
        return None

    def check_database(self, database_version: bytes) -> int:
        """
        Ensure the proper schema is used by the database.

        :param database_version: Current version of the database.
        :returns: None.
        """
        assert database_version.isdigit()
        assert int(database_version) >= 0
        idatabase_version = int(database_version) or self.LATEST_DB_VERSION

        if idatabase_version < self.LATEST_DB_VERSION:
            while idatabase_version < self.LATEST_DB_VERSION:
                upgrade_script = self.get_upgrade_script(current_version=idatabase_version)
                if upgrade_script:
                    self.executescript(upgrade_script)
                idatabase_version += 1

        self.executescript(self.get_schema(idatabase_version))
        self.commit()

        return self.LATEST_DB_VERSION
