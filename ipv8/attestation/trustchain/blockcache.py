from ...database import database_blob


class BlockCache(object):
    """
    This class will cache (originating and linked) blocks in the chain of this user.
    """

    def __init__(self, database, public_key):
        self.database = database
        self.public_key = public_key
        self.blocks = {}          # Dictionary to hold known blocks (keys: sequence number, value: block)
        self.linked_blocks = {}   # Dictionary to hold linked blocks (keys: sequence number, value: block)

    def add(self, block):
        """
        Add a TrustChain block to the cache.
        :param block: The block to add.
        """
        if block.public_key == self.public_key:
            self.blocks[block.sequence_number] = block
        else:
            self.linked_blocks[block.sequence_number] = block

    def get_range(self, start_seq_num, end_seq_num):
        missing = self.get_missing_in_range(start_seq_num, end_seq_num)
        if missing:
            # We are missing some blocks in our own chain, fetch them from the database
            missing_str = ','.join(["%d" % seq_num for seq_num in missing])
            query = u"SELECT * FROM (%s WHERE sequence_number IN (%s) AND public_key = ?) " \
                    u"UNION SELECT * FROM (%s WHERE link_sequence_number IN (%s) AND " \
                    u"link_sequence_number != 0 AND link_public_key = ?)" % \
                    (self.database.get_sql_header(), missing_str, self.database.get_sql_header(), missing_str)
            db_result = list(self.database.execute(query,
                                                   (database_blob(self.public_key), database_blob(self.public_key)),
                                                   fetch_all=True))
            blocks = [self.database.get_block_class(db_item[0] if isinstance(db_item[0], bytes)
                                                    else str(db_item[0]).encode('utf-8'))(db_item)
                      for db_item in db_result]
            for block in blocks:  # Add them to the cache
                self.add(block)

        # Check whether we need to fetch blocks linked to linked blocks. These blocks are not fetched by our
        # SQL query unfortunately.
        for seq_num in range(start_seq_num, end_seq_num + 1):
            my_block = self.blocks.get(seq_num, None)
            if my_block and seq_num not in self.linked_blocks:
                linked_block = self.database.get_linked(my_block)
                if linked_block:
                    self.add(linked_block)
                else:
                    # Even if the linked block does not exist, we add a None value anyway.
                    # We do so to indicate that we have actually checked whether it exists.
                    self.linked_blocks[seq_num] = None

        # We now get all the blocks in the requested range
        blocks = []
        for seq_num in range(start_seq_num, end_seq_num + 1):
            my_block = self.blocks.get(seq_num, None)
            if my_block:
                blocks.append(my_block)
                linked_block = self.linked_blocks.get(seq_num, None)
                if linked_block:
                    blocks.append(linked_block)

        return blocks

    def get_missing_in_range(self, start_seq_num, end_seq_num):
        """
        Get all the sequence numbers that are missing within a given range.
        """
        missing = []
        for seq_num in range(start_seq_num, end_seq_num + 1):
            if seq_num not in self.blocks:
                missing.append(seq_num)

        return missing
