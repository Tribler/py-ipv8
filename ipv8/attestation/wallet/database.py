import os

from ...database import Database, database_blob

DATABASE_DIRECTORY = os.path.join(u"sqlite")


class AttestationsDB(Database):

    LATEST_DB_VERSION = 2

    def __init__(self, working_directory, db_name):
        """
        Sets up the persistence layer ready for use.
        :param working_directory: Path to the working directory
        that will contain the the db at working directory/DATABASE_PATH
        :param db_name: The name of the database
        """
        if working_directory != u":memory:":
            db_path = os.path.join(working_directory, os.path.join(DATABASE_DIRECTORY, u"%s.db" % db_name))
        else:
            db_path = working_directory
        super(AttestationsDB, self).__init__(db_path)
        self.db_name = db_name
        self.open()

    def _get(self, query, params):
        return list(self.execute(query, params, fetch_all=False))

    def get_attestation_by_hash(self, attestation_hash):
        return self._get(u"SELECT blob FROM %s WHERE hash = ?" % self.db_name, (database_blob(attestation_hash),))

    def get_all(self):
        return list(self.execute(u"SELECT * FROM %s" % self.db_name, (), fetch_all=True))

    def insert_attestation(self, attestation, attestation_hash, secret_key, id_format):
        blob = database_blob(attestation.serialize_private(secret_key.public_key()))
        self.execute(
            u"INSERT INTO %s (hash, blob, key, id_format) VALUES(?,?,?,?)" % self.db_name,
            (database_blob(attestation_hash), blob, database_blob(secret_key.serialize()),
             database_blob(id_format.encode('utf-8'))))
        self.commit()

    def get_schema(self, version):
        """
        Return the schema for the database.
        """
        schema = u""
        if version == 1:
            schema = u"""
                     CREATE TABLE IF NOT EXISTS %s(
                     hash                 BLOB,
                     blob                 LONGBLOB,
                     key                  MEDIUMBLOB

                     PRIMARY KEY (hash)
                     );
                     """ % self.db_name
        elif version == 2:
            schema = u"""
                     CREATE TABLE IF NOT EXISTS %s(
                     hash                 BLOB,
                     blob                 LONGBLOB,
                     key                  MEDIUMBLOB,
                     id_format            TINYTEXT,

                     PRIMARY KEY (hash)
                     );
                     """ % self.db_name
        schema += u"""
                  CREATE TABLE IF NOT EXISTS option(key TEXT PRIMARY KEY, value BLOB);
                  DELETE FROM option WHERE key = 'database_version';
                  INSERT INTO option(key, value) VALUES('database_version', '%s');
                  """ % str(self.LATEST_DB_VERSION)
        return schema

    def get_upgrade_script(self, current_version):
        """
        Return the upgrade script for a specific version.
        :param current_version: the version of the script to return.
        """
        if current_version == 1:
            return u"""
                    ALTER TABLE %s
                    ADD id_format TINYTEXT;

                    UPDATE %s SET id_format='id_metadata';
                    """ % (self.db_name, self.db_name)
        else:
            return None

    def check_database(self, database_version):
        """
        Ensure the proper schema is used by the database.
        :param database_version: Current version of the database.
        :return:
        """
        assert database_version.isdigit()
        assert int(database_version) >= 0
        database_version = int(database_version) or self.LATEST_DB_VERSION

        if database_version < self.LATEST_DB_VERSION:
            while database_version < self.LATEST_DB_VERSION:
                upgrade_script = self.get_upgrade_script(current_version=database_version)
                if upgrade_script:
                    self.executescript(upgrade_script)
                database_version += 1

        self.executescript(self.get_schema(database_version))
        self.commit()

        return self.LATEST_DB_VERSION
