"""
This file contains everything related to persistence for TrustChain.
"""
import os

from ...database import Database
from .block import TrustChainBlock


DATABASE_DIRECTORY = os.path.join(u"sqlite")


class TrustChainDB(Database):
    """
    Persistence layer for the TrustChain Community.
    Connection layer to SQLiteDB.
    Ensures a proper DB schema on startup.
    """
    LATEST_DB_VERSION = 1

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
        super(TrustChainDB, self).__init__(db_path)
        self._logger.debug("TrustChain database path: %s", db_path)
        self.db_name = db_name
        self.open()

    def add_block(self, block):
        """
        Persist a block
        :param block: The data that will be saved.
        """
        self.execute(
            u"INSERT INTO blocks (tx, public_key, sequence_number, link_public_key,"
            u"link_sequence_number, previous_hash, signature, block_timestamp, block_hash) VALUES(?,?,?,?,?,?,?,?,?)",
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
            u"DELETE FROM blocks WHERE tx = ? AND public_key = ? AND sequence_number = ? AND link_public_key = ? AND "
            u"link_sequence_number = ? AND previous_hash = ? AND signature = ? AND block_timestamp = ? " \
            u"AND block_hash = ?",
            block.pack_db_insert())
        self.commit()

    def _get(self, query, params):
        db_result = list(self.execute(self.get_sql_header() + query, params, fetch_all=False))
        return TrustChainBlock(db_result) if db_result else None

    def _getall(self, query, params):
        db_result = list(self.execute(self.get_sql_header() + query, params, fetch_all=True))
        return [TrustChainBlock(db_item) for db_item in db_result]

    def get(self, public_key, sequence_number):
        """
        Get a specific block for a given public key
        :param public_key: The public_key for which the block has to be found.
        :param sequence_number: The specific block to get
        :return: the block or None if it is not known
        """
        return self._get(u"WHERE public_key = ? AND sequence_number = ?", (buffer(public_key), sequence_number))

    def contains(self, block):
        """
        Check if a block is existent in the persistence layer.
        :param block: the block to check
        :return: True if the block exists, else false.
        """
        return self.get(block.public_key, block.sequence_number) is not None

    def get_latest(self, public_key):
        """
        Get the latest block for a given public key
        :param public_key: The public_key for which the latest block has to be found.
        :return: the latest block or None if it is not known
        """
        return self._get(u"WHERE public_key = ? AND sequence_number = (SELECT MAX(sequence_number) FROM blocks "
                         u"WHERE public_key = ?)", (buffer(public_key), buffer(public_key)))

    def get_latest_blocks(self, public_key, limit=25):
        return self._getall(u"WHERE public_key = ? ORDER BY sequence_number DESC LIMIT ?", (buffer(public_key), limit))

    def get_block_after(self, block):
        """
        Returns database block with the lowest sequence number higher than the block's sequence_number
        :param block: The block who's successor we want to find
        :return A block
        """
        return self._get(u"WHERE sequence_number > ? AND public_key = ? ORDER BY sequence_number ASC",
                         (block.sequence_number, buffer(block.public_key)))

    def get_block_before(self, block):
        """
        Returns database block with the highest sequence number lower than the block's sequence_number
        :param block: The block who's predecessor we want to find
        :return A block
        """
        return self._get(u"WHERE sequence_number < ? AND public_key = ? ORDER BY sequence_number DESC",
                         (block.sequence_number, buffer(block.public_key)))

    def get_lowest_sequence_number_unknown(self, public_key):
        """
        Return the lowest sequence number that we don't have a block of in the chain of a specific peer.
        :param public_key: The public key
        """
        query = u"SELECT b1.sequence_number FROM blocks b1 WHERE b1.public_key = ? AND NOT EXISTS " \
                u"(SELECT b2.sequence_number FROM blocks b2 WHERE b2.sequence_number = b1.sequence_number + 1 " \
                u"AND b2.public_key = ?) ORDER BY b1.sequence_number LIMIT 1"
        db_result = list(self.execute(query, (buffer(public_key), buffer(public_key)), fetch_all=True))
        return db_result[0][0] + 1 if db_result else 1

    def get_linked(self, block):
        """
        Get the block that is linked to the given block
        :param block: The block for which to get the linked block
        :return: the latest block or None if it is not known
        """
        return self._get(u"WHERE public_key = ? AND sequence_number = ? OR link_public_key = ? AND "
                         u"link_sequence_number = ?", (buffer(block.link_public_key), block.link_sequence_number,
                                                       buffer(block.public_key), block.sequence_number))

    def crawl(self, public_key, sequence_number, limit=100):
        assert limit <= 100, "Don't fetch too much"
        return self._getall(u"WHERE insert_time >= (SELECT MAX(insert_time) FROM blocks WHERE public_key = ? AND "
                            u"sequence_number <= ?) AND (public_key = ? OR link_public_key = ?) "
                            u"ORDER BY insert_time ASC LIMIT ?",
                            (buffer(public_key), sequence_number, buffer(public_key), buffer(public_key), limit))

    def get_sql_header(self):
        """
        Return the first part of a generic sql select query.
        """
        _columns = u"tx, public_key, sequence_number, link_public_key, link_sequence_number, " \
                   u"previous_hash, signature, block_timestamp, insert_time"
        return u"SELECT " + _columns + u" FROM blocks "

    def get_schema(self):
        """
        Return the schema for the database.
        """
        return u"""
        CREATE TABLE IF NOT EXISTS blocks(
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
        return None

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
        assert isinstance(database_version, unicode)
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
