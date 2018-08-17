from hashlib import sha1
import os

from ...database import Database

DATABASE_DIRECTORY = os.path.join("sqlite")


class AttestationsDB(Database):

    LATEST_DB_VERSION = 1

    def __init__(self, working_directory, db_name):
        """
        Sets up the persistence layer ready for use.
        :param working_directory: Path to the working directory
        that will contain the the db at working directory/DATABASE_PATH
        :param db_name: The name of the database
        """
        if working_directory != ":memory:":
            db_path = os.path.join(working_directory, os.path.join(DATABASE_DIRECTORY, "%s.db" % db_name))
        else:
            db_path = working_directory
        super(AttestationsDB, self).__init__(db_path)
        self.db_name = db_name
        self.open()

    def _get(self, query, params):
        return list(self.execute(query, params, fetch_all=False))

    def get_attestation_by_hash(self, hash):
        return self._get("SELECT blob FROM %s WHERE hash = ?" % self.db_name, (hash,))

    def get_all(self):
        return list(self.execute("SELECT * FROM %s" % self.db_name, (), fetch_all=True))

    def insert_attestation(self, attestation, secret_key):
        blob = attestation.serialize()
        hash = sha1(blob).digest()
        self.execute(
            "INSERT INTO %s (hash, blob, key) VALUES(?,?,?)" % self.db_name,
            (hash, blob, secret_key.serialize()))
        self.commit()

    def get_schema(self):
        """
        Return the schema for the database.
        """
        return """
        CREATE TABLE IF NOT EXISTS %s(
         hash                 BLOB,
         blob                 LONGBLOB,
         key                  MEDIUMBLOB,

         PRIMARY KEY (hash)
         );

        CREATE TABLE option(key TEXT PRIMARY KEY, value BLOB);
        INSERT INTO option(key, value) VALUES('database_version', '%s');
        """ % (self.db_name, str(self.LATEST_DB_VERSION))

    def get_upgrade_script(self, current_version):
        """
        Return the upgrade script for a specific version.
        :param current_version: the version of the script to return.
        """
        return None

    def check_database(self, database_version):
        """
        Ensure the proper schema is used by the database.
        :param database_version: Current version of the database.
        :return:
        """
        assert isinstance(database_version, str)
        assert database_version.isdigit()
        assert int(database_version) >= 0
        database_version = int(database_version)

        if database_version < self.LATEST_DB_VERSION:
            while database_version < self.LATEST_DB_VERSION:
                upgrade_script = self.get_upgrade_script(current_version=database_version)
                if upgrade_script:
                    self.executescript(upgrade_script)
                database_version += 1
            self.executescript(self.get_schema())
            self.commit()

        return self.LATEST_DB_VERSION
