"""
This file contains everything related to persistence for TrustChain.
"""
import os

from ...database import Database
from .block import TrustChainBlock


DATABASE_DIRECTORY = os.path.join("sqlite")


class TrustChainDB(Database):
    """
    Persistence layer for the TrustChain Community.
    Connection layer to SQLiteDB.
    Ensures a proper DB schema on startup.
    """
    LATEST_DB_VERSION = 5

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
        super(TrustChainDB, self).__init__(db_path)
        self._logger.debug("TrustChain database path: %s", db_path)
        self.db_name = db_name
        self.block_types = {}
        self.open()

    def get_block_class(self, block_type):
        """
        Get the block class for a specific block type.
        """
        if block_type not in self.block_types:
            return TrustChainBlock

        return self.block_types[block_type]

    def add_block(self, block):
        """
        Persist a block
        :param block: The data that will be saved.
        """
        self.execute(
            "INSERT INTO blocks (type, tx, public_key, sequence_number, link_public_key,"
            "link_sequence_number, previous_hash, signature, block_timestamp, block_hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
            block.pack_db_insert())
        self.commit()

    def remove_block(self, block):
        """
        DANGER! USING THIS WILL LIKELY CAUSE A DOUBLE-SPEND IN THE NETWORK.
                ONLY USE IF YOU KNOW WHAT YOU ARE DOING.
        Remove a block from the database.

        :param block: The data that will be removed.
        """
        self.execute(
            "DELETE FROM blocks WHERE type = ? AND tx = ? AND public_key = ? AND sequence_number = ? AND "
            "link_public_key = ? AND link_sequence_number = ? AND previous_hash = ? AND signature = ? "
            "AND block_timestamp = ? AND block_hash = ?",
            block.pack_db_insert())
        self.commit()

    def _get(self, query, params):
        db_result = list(self.execute(self.get_sql_header() + query, params, fetch_all=False))
        return self.get_block_class(db_result[0])(db_result) if db_result else None

    def _getall(self, query, params):
        db_result = list(self.execute(self.get_sql_header() + query, params, fetch_all=True))
        return [self.get_block_class(db_item[0])(db_item) for db_item in db_result]

    def get(self, public_key, sequence_number):
        """
        Get a specific block for a given public key
        :param public_key: The public_key for which the block has to be found.
        :param sequence_number: The specific block to get
        :return: the block or None if it is not known
        """
        return self._get("WHERE public_key = ? AND sequence_number = ?", (public_key, sequence_number))

    def get_all_blocks(self):
        """
        Return all blocks in the database.
        :return: all blocks in the database
        """
        return self._getall("", ())

    def get_block_with_hash(self, block_hash):
        """
        Return the block with a specific hash or None if it's not available in the database.
        :param block_hash: the hash of the block to search for.
        """
        return self._get("WHERE block_hash = ?", (buffer(block_hash),))

    def get_blocks_with_type(self, block_type, public_key=None):
        """
        Return all blocks with a specific type.
        :param block_type: the type of the block we want to fetch.
        :param public_key: specify if we want only blocks of a specific peer.
        :return: All blocks with a specific type, optionally of a specific peer.
        """
        if public_key:
            return self._getall("WHERE type = ? and public_key = ?", (block_type, buffer(public_key)))
        return self._getall("WHERE type = ?", (block_type,))

    def contains(self, block):
        """
        Check if a block is existent in the persistence layer.
        :param block: the block to check
        :return: True if the block exists, else false.
        """
        return self.get(block.public_key, block.sequence_number) is not None

    def get_latest(self, public_key, block_type=None):
        """
        Get the latest block for a given public key
        :param public_key: The public_key for which the latest block has to be found.
        :param block_type: A block type (optional). When specified, it returned the latest block of this type.
        :return: the latest block or None if it is not known
        """
        if block_type:
            return self._get("WHERE public_key = ? AND type = ? AND sequence_number = (SELECT MAX(sequence_number) "
                             "FROM blocks WHERE public_key = ? AND type = ?)",
                             (public_key, block_type, public_key, block_type))
        else:
            return self._get("WHERE public_key = ? AND sequence_number = (SELECT MAX(sequence_number) FROM blocks "
                             "WHERE public_key = ?)", (public_key, public_key))

    def get_latest_blocks(self, public_key, limit=25, block_type=None):
        if block_type:
            return self._getall("WHERE public_key = ? AND type = ? ORDER BY sequence_number DESC LIMIT ?",
                                (buffer(public_key), block_type, limit))
        else:
            return self._getall("WHERE public_key = ? ORDER BY sequence_number DESC LIMIT ?",
                                (buffer(public_key), limit))

    def get_block_after(self, block, block_type=None):
        """
        Returns database block with the lowest sequence number higher than the block's sequence_number
        :param block: The block who's successor we want to find
        :param block_type: A block type (optional). When specified, it only considers blocks of this type
        :return A block
        """
        if block_type:
            return self._get("WHERE sequence_number > ? AND public_key = ? AND type = ? ORDER BY sequence_number ASC",
                             (block.sequence_number, block.public_key, block_type))
        else:
            return self._get("WHERE sequence_number > ? AND public_key = ? ORDER BY sequence_number ASC",
                             (block.sequence_number, block.public_key))

    def get_block_before(self, block, block_type=None):
        """
        Returns database block with the highest sequence number lower than the block's sequence_number
        :param block: The block who's predecessor we want to find
        :return A block
        """
        if block_type:
            return self._get("WHERE sequence_number < ? AND public_key = ? AND type = ? ORDER BY sequence_number DESC",
                             (block.sequence_number, block.public_key, block_type))
        else:
            return self._get("WHERE sequence_number < ? AND public_key = ? ORDER BY sequence_number DESC",
                             (block.sequence_number, block.public_key))

    def get_lowest_sequence_number_unknown(self, public_key):
        """
        Return the lowest sequence number that we don't have a block of in the chain of a specific peer.
        :param public_key: The public key
        """
        query = "SELECT b1.sequence_number FROM blocks b1 WHERE b1.public_key = ? AND NOT EXISTS " \
                "(SELECT b2.sequence_number FROM blocks b2 WHERE b2.sequence_number = b1.sequence_number + 1 " \
                "AND b2.public_key = ?) ORDER BY b1.sequence_number LIMIT 1"
        db_result = list(self.execute(query, (public_key, public_key), fetch_all=True))
        return db_result[0][0] + 1 if db_result else 1

    def get_linked(self, block):
        """
        Get the block that is linked to the given block
        :param block: The block for which to get the linked block
        :return: the latest block or None if it is not known
        """
        return self._get("WHERE public_key = ? AND sequence_number = ? OR link_public_key = ? AND "
                         "link_sequence_number = ?", (block.link_public_key, block.link_sequence_number,
                                                      block.public_key, block.sequence_number))

    def crawl(self, public_key, sequence_number, limit=100):
        assert limit <= 100, "Don't fetch too much"
        return self._getall("WHERE insert_time >= (SELECT MAX(insert_time) FROM blocks WHERE public_key = ? AND "
                            "sequence_number <= ?) AND (public_key = ? OR link_public_key = ?) "
                            "ORDER BY insert_time ASC LIMIT ?",
                            (public_key, sequence_number, public_key, public_key, limit))

    def get_sql_header(self):
        """
        Return the first part of a generic sql select query.
        """
        _columns = "type, tx, public_key, sequence_number, link_public_key, link_sequence_number, " \
                   "previous_hash, signature, block_timestamp, insert_time"
        return "SELECT " + _columns + " FROM blocks "

    def get_schema(self):
        """
        Return the schema for the database.
        """
        return """
        CREATE TABLE IF NOT EXISTS blocks(
         type                 TEXT NOT NULL,
         tx                   TEXT NOT NULL,
         public_key           TEXT NOT NULL,
         sequence_number      INTEGER NOT NULL,
         link_public_key      TEXT NOT NULL,
         link_sequence_number INTEGER NOT NULL,
         previous_hash	      TEXT NOT NULL,
         signature		      TEXT NOT NULL,
         block_timestamp      BIGINT NOT NULL,
         insert_time          TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
         block_hash	          TEXT NOT NULL,

         PRIMARY KEY (public_key, sequence_number)
         );

        CREATE TABLE option(key TEXT PRIMARY KEY, value BLOB);
        INSERT INTO option(key, value) VALUES('database_version', '%s');

        CREATE INDEX pub_key_ind ON blocks (public_key);
        CREATE INDEX link_pub_key_ind ON blocks (link_public_key);
        CREATE INDEX seq_num_ind ON blocks (sequence_number);
        CREATE INDEX link_seq_num_ind ON blocks (link_sequence_number);
        """ % str(self.LATEST_DB_VERSION)

    def get_upgrade_script(self, current_version):
        """
        Return the upgrade script for a specific version.
        :param current_version: the version of the script to return.
        """
        if current_version <= 4:  # All these version introduce changes that are not backwards compatible
            return """
            DROP TABLE IF EXISTS blocks;
            DROP TABLE IF EXISTS option;
            """

    def open(self, initial_statements=True, prepare_visioning=True):
        return super(TrustChainDB, self).open(initial_statements, prepare_visioning)

    def close(self, commit=True):
        return super(TrustChainDB, self).close(commit)

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
