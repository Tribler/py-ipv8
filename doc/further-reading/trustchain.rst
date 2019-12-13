TrustChain
==========

This document entails a high-level overview of the implementation of TrustChain in IPv8.
TrustChain is a scalable, tamper-proof and distributed ledger, built for secure accounting.
For more information about TrustChain itself, we refer to our `IETF internet standard <https://tools.ietf.org/html/draft-pouwelse-trustchain-01>`_.
Additional information can be found `in our published scientific article <https://www.sciencedirect.com/science/article/pii/S0167739X17318988>`_ and our ` vision paper describing various applications using TrustChain <http://pure.tudelft.nl/ws/files/41225519/article.pdf>`_.

Overview
--------

The key idea of TrustChain is that each peer maintains its own *individual ledger* with transaction.
A transaction between two peers consists of two types of blocks: a *proposal* block, created by the initiator of the transaction, and an *agreement* block, created by the counterparty.
The TrustChain implementation refers to these blocks as *half blocks*.
During a transaction, a peer adds local information regarding a transaction to a half block, and commits to this information by adding its digital signature to the half block.

A transaction between peer A and B proceeds as follows.
First, peer A creates a *proposal* block, digitally signs it, and sends the proposal block to peer B.
When peer B receives the proposal block, it assesses the validity of the proposal block and inspects the transaction content.
If peer B does not agree with the transaction data, it ignores the received block.
Otherwise, peer B creates an *agreement* block, digitally signs it, and sends it back to peer A.
Agreement of both parties can now be proven to other peers by revealing the block created by peers A and B.

Newly created blocks are immediately appended to the individual ledger of their creator.
Each individual ledger contains all transactions that a specific peer participated in, in chronological order.
Each block, except for the first block in the individual ledger, contains a pointer to the prior block.
Modifications of the individual ledger can be detected and proven by transaction counterparties.

Implementation
--------------

The TrustChain implementation is provided in 4 files:


* ``block.py``\ : this file defines the data structure of a block in the TrustChain ledger
* ``community.py``\ : the ipv8 overlay providing higher order TrustChain logic (i.e. handling incoming blocks and exploring other blocks in the network)
* ``database.py``\ : wrapper to query and update the database with known TrustChain blocks
* ``payload.py``\ : defines the message format and data structures for communication between peers

The logic present in each file is now briefly explained.

block.py
--------

The ``block.py`` file contains the definition of a TrustChain half block (in the ``TrustChainBlock`` class).
Note that each valid transaction contains exactly two blocks, signed by both involved parties.
Each block in TrustChain contains the following properties:

.. list-table::
   :header-rows: 1

   * - Property
     - Type
     - Description
   * - *type*
     - string
     - The type of the block. Can be any arbitrary string.
   * - *transaction*
     - dictionary
     - The transaction that this block describes.
   * - *public\_key*
     - string
     - The public key in binary format of the block creator.
   * - *link\_public\_key*
     - string
     - The public key of the transaction counterparty.
   * - *sequence\_number*
     - integer
     - The sequence number of the block. The sequence number of the genesis block is 1.
   * - *link\_sequence\_number*
     - integer
     - The sequence number of the linked block.
   * - *previous\_hash*
     - string
     - The SHA256 hash of the previous block in the chain.
   * - *signature*
     - string
     - The signature of the block.
   * - *timestamp*
     - integer
     - The epoch timestamp defining when this block is created (with milliseconds precision).


The attributes within the ``TrustChainBlock`` class have a high overlap with those in a ``HalfBlockPayload``.

Block Validation
^^^^^^^^^^^^^^^^

Each incoming block and new block created are verified for correctness.
These checks are performed by the ``validate`` method inside the ``TrustChainBlock`` class.
Discovered blocks that are invalid are ignored and not added to the database.
The validation method also aims to detect fraudulent operations performed by users, such as a double-spend attack.

payload.py
----------

TrustChain defines six different messages types, used to request signatures in blocks and exchange knowledge of existing blocks.
We now describe the functionality of each message:

.. list-table::
   :header-rows: 1

   * - Name
     - Description
   * - *CrawlRequestPayload*
     - This message describes a crawl request for another user. It contains the public key of the receiver of the crawl request, the index of the block(s) being requested and a random identifier.
   * - *CrawlResponsePayload*
     - Response to a *CrawlRequest* message. Contains a TrustChain block, the crawl identifier, the total amount of blocks being sent during the crawl, and the index of this block during the crawl.
   * - *HalfBlockPayload*
     - Contains a single half block.
   * - *HalfBlockBroadcastPayload*
     - Contains a single half block and a TTL value.
   * - *HalfBlockPairPayload*
     - Contains a pair of half blocks.
   * - *HalfBlockPairBroadcastPayload*
     - Contains a pair of half blocks and a TTL value.


The sequence number in the *CrawlRequestPayload* specifies from which sequence number forward, blocks will be sent back (up to 100 blocks in response).
Alternatively, the sequence number can also be negative.
A negative sequence number implies the offset from the last block.
For example, when peer **A** performs a crawl request from a peer **B** with 8 blocks (numbered 1 through 8):

.. list-table::
   :header-rows: 1

   * - **A** request
     - **B** response
   * - CrawlRequest(1)
     - 1, 2, 3, 4, 5, 6, 7, 8
   * - CrawlRequest(3)
     - 3, 4, 5, 6, 7, 8
   * - CrawlRequest(0)
     - 1, 2, 3, 4, 5, 6, 7, 8
   * - CrawlRequest(-1)
     - 8
   * - CrawlRequest(-5)
     - 4, 5, 6, 7, 8
   * - CrawlRequest(9)
     - 


The ``HalfBlockPayload`` class is used to share a block.
It is sent when a transaction is being made.
Upon receipt, the TrustChain logic will determine if the block is valid and/or other blocks need to be crawled to validate the received block.

* NOTE: The *link_sequence_number* of the party requesting the transaction be signed is always 0.
  The blocks are only linked by sequence number through the second "half" of the block.
  Therefore, you should always use ``get_linked()`` defined in ``database.py`` to retrieve a block's other half.

database.py
-----------

The ``database.py`` file defines the TrustChain database class.
This database class is responsible for (1) storing and (2) querying blocks in the database, of both the owner and crawled third parties.
One can either access this data structure as a linked list, or by index reference (sequence number).

Various methods are defined to fetch information from the TrustChain database in a structured manner:


* ``contains(block)`` to check whether a specific block is stored in the database.
* ``get_latest(public_key, block_type=None)`` to get the last block for a specific peer with a public key.
* ``get_latest_blocks(public_key, limit=25)`` to get the tail of the chain for some peer.
* ``get_block_after(block, block_type=None)`` to get the next block in a chain, after a specified block.
* ``get_block_before(block, block_type=None)`` to get the previous block in a chain, before a specified block.
* ``get_lowest_sequence_number_unknown(public_key)`` to get the lowest sequence number of the block we do not have (yet).
* ``get_linked()`` to get the linked block from another chain (if available).
* ``get_all_blocks()`` to get all blocks stored in the database.
* ``get_block_with_hash(hash)`` to get the block with a specific hash (if available).
* ``get_blocks_with_type(self, block_type, public_key=None)`` to get all blocks with a specific type and optionally with a public key.

For indexed usage, one can use:


* ``get(public_key, sequence_number)`` to get a specific block for a specific peer and manually read the ``TrustChainBlock``.

As previously mentioned, do bear in mind that the *link_sequence_number* will always be 0 for the transactor and non-zero for the transactee.
As such, *link_sequence_number* should never be used to perform a subsequent ``get``\ : the ``get_linked`` method should be used instead.

community.py
------------

The ``community.py`` file defines the higher order TrustChain logic, in particular, in the ``TrustChainCommunity`` class.
This class maintains a database object (\ ``persistence``\ ) and decides when to send messages to other peers.
Additionally, this class also provides the method for creating blocks: ``sign_block()``.
Invoking this method with the correct parameters should sent a half block to a counterparty for signing.
This method returns a ``Deferred`` object which fires when the counterparty has created their half block and has sent it back to us.
Developers can interact with the chain by defining listeners, which can trigger specific actions on receiving blocks.

Listeners
^^^^^^^^^

To manage creation and update procedure of TrustChain blocks with a specific type, one should define and create a ``BlockListener`` object.
Each ``BlockListener`` class should define the following two methods:


* ``should_sign(block)``\ : returns whether the block should be signed or not.
* ``received_block(block)``\ : invoked when the TrustChain community receives a block that matches with the block type that the listener listens to.

To add a listener to the TrustChain community, one should use the ``add_listener`` method, which takes a ``BlockListener`` object and a list of block types that this listener listens to.
