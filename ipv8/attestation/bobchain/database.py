"""
This file contains everything related to persistence for TrustChain.
"""
from __future__ import absolute_import

from binascii import hexlify
import os

from .block import BobChainBlock
from ...database import database_blob, Database
from ...util import is_unicode

DATABASE_DIRECTORY = os.path.join(u"sqlite")


class BobChainDB(Database):
    """
    Persistence layer for the BobChain Community.
    Connection layer to SQLiteDB.
    Ensures a proper DB schema on startup.
    """
    LATEST_DB_VERSION = 7

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
        super(BobChainDB, self).__init__(db_path)
        self._logger.debug("TrustChain database path: %s", db_path)
        self.db_name = db_name
        self.block_types = {}
        self.open()

    def get_block_class(self, block_type):
        """
        Get the block class for a specific block type.
        """
        if block_type not in self.block_types:
            return BobChainBlock

        return self.block_types[block_type]

    def add_block(self, block):
        """
        Persist a block
        :param block: The data that will be saved.
        """
        self.execute(
            u"INSERT INTO blocks (type, tx, public_key, sequence_number, link_public_key,"
            u"link_sequence_number, previous_hash, signature, block_timestamp, block_hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
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
            u"DELETE FROM blocks WHERE type = ? AND tx = ? AND public_key = ? AND sequence_number = ? AND "
            u"link_public_key = ? AND link_sequence_number = ? AND previous_hash = ? AND signature = ? "
            u"AND block_timestamp = ? AND block_hash = ?",
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
        return self._get(u"WHERE public_key = ? AND sequence_number = ?", (database_blob(public_key), sequence_number))

    def get_all_blocks(self):
        """
        Return all blocks in the database.
        :return: all blocks in the database
        """
        return self._getall(u"", ())

    def get_number_of_known_blocks(self, public_key=None):
        """
        Return the total number of blocks in the database or the number of known blocks for a specific user.
        """
        if public_key:
            return list(self.execute(u"SELECT COUNT(*) FROM blocks WHERE public_key = ?",
                                     (database_blob(public_key),)))[0][0]
        return list(self.execute(u"SELECT COUNT(*) FROM blocks"))[0][0]

    def remove_old_blocks(self, num_blocks_to_remove, my_pub_key):
        """
        Remove old blocks from the database.
        :param num_blocks_to_remove: The number of blocks to remove from the database.
        :param my_pub_key: Your public key, specified since we don't want to remove your own blocks.
        """
        self.execute(u"DELETE FROM blocks WHERE block_hash IN "
                     u"(SELECT block_hash FROM blocks WHERE public_key != ? ORDER BY block_timestamp LIMIT ?)",
                     (database_blob(my_pub_key), num_blocks_to_remove))

    def get_block_with_hash(self, block_hash):
        """
        Return the block with a specific hash or None if it's not available in the database.
        :param block_hash: the hash of the block to search for.
        """
        return self._get(u"WHERE block_hash = ?", (database_blob(block_hash),))

    def get_blocks_with_type(self, block_type, public_key=None):
        """
        Return all blocks with a specific type.
        :param block_type: the type of the block we want to fetch.
        :param public_key: specify if we want only blocks of a specific peer.
        :return: All blocks with a specific type, optionally of a specific peer.
        """
        if public_key:
            return self._getall(u"WHERE type = ? and public_key = ?", (block_type, database_blob(public_key)))
        return self._getall(u"WHERE type = ?", (block_type,))

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
            return self._get(u"WHERE public_key = ? AND type = ? AND sequence_number = (SELECT MAX(sequence_number) "
                             u"FROM blocks WHERE public_key = ? AND type = ?)",
                             (database_blob(public_key), block_type, database_blob(public_key), block_type))
        else:
            return self._get(u"WHERE public_key = ? AND sequence_number = (SELECT MAX(sequence_number) FROM blocks "
                             u"WHERE public_key = ?)", (database_blob(public_key), database_blob(public_key)))

    def get_latest_blocks(self, public_key, limit=25, block_type=None):
        if block_type:
            return self._getall(u"WHERE public_key = ? AND type = ? ORDER BY sequence_number DESC LIMIT ?",
                                (database_blob(public_key), block_type, limit))
        else:
            return self._getall(u"WHERE public_key = ? ORDER BY sequence_number DESC LIMIT ?",
                                (database_blob(public_key), limit))

    def get_block_after(self, block, block_type=None):
        """
        Returns database block with the lowest sequence number higher than the block's sequence_number
        :param block: The block who's successor we want to find
        :param block_type: A block type (optional). When specified, it only considers blocks of this type
        :return A block
        """
        if block_type:
            return self._get(u"WHERE sequence_number > ? AND public_key = ? AND type = ? ORDER BY sequence_number ASC",
                             (block.sequence_number, database_blob(block.public_key), block_type))
        else:
            return self._get(u"WHERE sequence_number > ? AND public_key = ? ORDER BY sequence_number ASC",
                             (block.sequence_number, database_blob(block.public_key)))

    def get_block_before(self, block, block_type=None):
        """
        Returns database block with the highest sequence number lower than the block's sequence_number
        :param block: The block who's predecessor we want to find
        :return A block
        """
        if block_type:
            return self._get(u"WHERE sequence_number < ? AND public_key = ? AND type = ? ORDER BY sequence_number DESC",
                             (block.sequence_number, database_blob(block.public_key), block_type))
        else:
            return self._get(u"WHERE sequence_number < ? AND public_key = ? ORDER BY sequence_number DESC",
                             (block.sequence_number, database_blob(block.public_key)))

    def get_lowest_sequence_number_unknown(self, public_key):
        """
        Return the lowest sequence number that we don't have a block of in the chain of a specific peer.
        :param public_key: The public key
        """

        # The following query fetches the earliest block that does not have a subsequent block.
        # This does not work for the case where we are merely missing the first block, hence this check.
        if not self.get(public_key, 1):
            return 1

        query = u"SELECT b1.sequence_number FROM blocks b1 WHERE b1.public_key = ? AND NOT EXISTS " \
                u"(SELECT b2.sequence_number FROM blocks b2 WHERE b2.sequence_number = b1.sequence_number + 1 " \
                u"AND b2.public_key = ?) ORDER BY b1.sequence_number LIMIT 1"
        db_result = list(self.execute(query, (database_blob(public_key), database_blob(public_key)), fetch_all=True))
        return db_result[0][0] + 1 if db_result else 1

    def get_lowest_range_unknown(self, public_key):
        """
        Get the range of blocks (created by the peer with public_key) that we do not have yet.
        For instance, if a user has the following blocks in the database: [1, 4, 5, 9], then this method will return
        the tuple (2, 3).
        :param public_key: The public key of the peer we want to get missing blocks from.
        :return: A tuple indicating the start and end of the range of missing blocks.
        """
        lowest_unknown = self.get_lowest_sequence_number_unknown(public_key)

        # Now get the sequence number of the first block in the database, after this lowest unknown
        query = u"SELECT sequence_number FROM blocks WHERE public_key = ? AND sequence_number > ? " \
                u"ORDER BY sequence_number LIMIT 1"
        db_result = list(self.execute(query, (database_blob(public_key), lowest_unknown), fetch_all=True))
        if db_result:
            return lowest_unknown, db_result[0][0] - 1
        else:
            return lowest_unknown, lowest_unknown

    def get_linked(self, block):
        """
        Get the block that is linked to the given block
        :param block: The block for which to get the linked block
        :return: the latest block or None if it is not known
        """
        return self._get(u"WHERE public_key = ? AND sequence_number = ? OR link_public_key = ? AND "
                         u"link_sequence_number = ? ORDER BY block_timestamp ASC",
                         (database_blob(block.link_public_key), block.link_sequence_number,
                          database_blob(block.public_key), block.sequence_number))

    def get_all_linked(self, block):
        """
        Return all linked blocks for a specific block.
        :param block: The block for which to get the linked block
        :return: A list of all linked blocks
        """
        return self._getall(u"WHERE public_key = ? AND sequence_number = ? OR link_public_key = ? AND "
                            u"link_sequence_number = ?", (database_blob(block.link_public_key),
                                                          block.link_sequence_number, database_blob(block.public_key),
                                                          block.sequence_number))

    def crawl(self, public_key, start_seq_num, end_seq_num, limit=100):
        query = u"SELECT * FROM (%s WHERE sequence_number >= ? AND sequence_number <= ? AND public_key = ? LIMIT ?) " \
                u"UNION SELECT * FROM (%s WHERE link_sequence_number >= ? AND link_sequence_number <= ? AND " \
                u"link_sequence_number != 0 AND link_public_key = ? LIMIT ?)" % \
                (self.get_sql_header(), self.get_sql_header())
        db_result = list(self.execute(query, (start_seq_num, end_seq_num, database_blob(public_key), limit,
                                              start_seq_num, end_seq_num, database_blob(public_key), limit),
                                      fetch_all=True))
        return [self.get_block_class(db_item[0])(db_item) for db_item in db_result]

    def get_recent_blocks(self, limit=10, offset=0):
        """
        Return the most recent blocks in the TrustChain database.
        """
        return self._getall(u"ORDER BY block_timestamp DESC LIMIT ? OFFSET ?", (limit, offset))

    def get_users(self, limit=100):
        """
        Return information about the users in the database
        """
        res = list(self.execute(
            u"SELECT DISTINCT public_key, MAX(sequence_number) FROM blocks GROUP BY public_key "
            u"ORDER BY MAX(sequence_number) DESC LIMIT ? ", (limit,)))
        users_info = []
        for user_info in res:
            users_info.append({
                "public_key": hexlify(user_info[0] if isinstance(user_info[0], bytes) else str(user_info[0])),
                "blocks": user_info[1],
            })
        return users_info

    def add_double_spend(self, block1, block2):
        """
        Add information about a double spend to the database.
        """
        sql = u"INSERT OR IGNORE INTO double_spends (type, tx, public_key, sequence_number, link_public_key," \
              u"link_sequence_number,previous_hash, signature, block_timestamp, block_hash) VALUES(?,?,?,?,?,?,?,?,?,?)"
        self.execute(sql, block1.pack_db_insert())
        self.execute(sql, block2.pack_db_insert())
        self.commit()

    def did_double_spend(self, public_key):
        """
        Return whether a specific user did a double spend in the past.
        """
        count = list(self.execute(u"SELECT COUNT(*) FROM double_spends WHERE public_key = ?",
                                  (database_blob(public_key),)))[0][0]
        return count > 0

    def get_sql_header(self):
        """
        Return the first part of a generic sql select query.
        """
        _columns = u"type, tx, public_key, sequence_number, link_public_key, link_sequence_number, " \
                   u"previous_hash, signature, block_timestamp, insert_time"
        return u"SELECT " + _columns + u" FROM blocks "

    def get_sql_create_blocks_table(self, table_name, primary_key):
        return u"""
        CREATE TABLE IF NOT EXISTS %s(
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

         PRIMARY KEY (%s)
         );
         """ % (table_name, primary_key)

    def get_schema(self):
        """
        Return the schema for the database.
        """
        return u"""
        %s

        %s

        CREATE TABLE IF NOT EXISTS option(key TEXT PRIMARY KEY, value BLOB);
        DELETE FROM option WHERE key = 'database_version';
        INSERT INTO option(key, value) VALUES('database_version', '%s');

        CREATE INDEX IF NOT EXISTS pub_key_ind ON blocks (public_key);
        CREATE INDEX IF NOT EXISTS link_pub_key_ind ON blocks (link_public_key);
        CREATE INDEX IF NOT EXISTS seq_num_ind ON blocks (sequence_number);
        CREATE INDEX IF NOT EXISTS link_seq_num_ind ON blocks (link_sequence_number);
        """ % (self.get_sql_create_blocks_table("blocks", "public_key, sequence_number"),
               self.get_sql_create_blocks_table("double_spends", "public_key, sequence_number, block_hash"),
               str(self.LATEST_DB_VERSION))

    def get_upgrade_script(self, current_version):
        """
        Return the upgrade script for a specific version.
        :param current_version: the version of the script to return.
        """
        # All these version introduce changes that are not backwards compatible
        if current_version <= 4 or current_version == 6:
            return u"""
            DROP TABLE IF EXISTS blocks;
            DROP TABLE IF EXISTS option;
            """
        elif current_version == 5:
            return self.get_sql_create_blocks_table("double_spends", "public_key, sequence_number, block_hash")

    def open(self, initial_statements=True, prepare_visioning=True):
        return super(BobChainDB, self).open(initial_statements, prepare_visioning)

    def close(self, commit=True):
        return super(BobChainDB, self).close(commit)

    def check_database(self, database_version):
        """
        Ensure the proper schema is used by the database.
        :param database_version: Current version of the database.
        :return:
        """
        assert is_unicode(database_version)
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
