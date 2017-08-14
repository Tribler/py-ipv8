This document entails the implementation of TrustChain in IPv8.
The implementation is provided in 4 files:

 - `block.py`: data structure of a block in the Blockchain
 - `community.py`: the ipv8 overlay providing higher order TrustChain logic
 - `database.py`: wrapper to query and update the database
 - `payload.py`: message format and datastructures for communication
 
## Payload

The TrustChain uses 2 messages to communicate between peers: a `CrawlRequest` and a `HalfBlock` message.

The `CrawlRequest` request message is sent when one peer wishes to receive blocks from another peer.
A `CrawlRequest` takes a sequence number as an argument.
This sequence number specifies from which sequence number forward, blocks will be sent back (up to 100 blocks in response).
Alternatively, the sequence number can also be negative.
A negative sequence number implies the offset from the last block.
For example, when peer **A** performs a crawl request from a peer **B** with 8 blocks (numbered 1 through 8):

| **A** request | **B** response |
| --- | --- |
| CrawlRequest(1) | 1, 2, 3, 4, 5, 6, 7, 8 |
| CrawlRequest(3) | 3, 4, 5, 6, 7, 8 |
| CrawlRequest(0) | 1, 2, 3, 4, 5, 6, 7, 8 |
| CrawlRequest(-1) | 8 |
| CrawlRequest(-5) | 4, 5, 6, 7, 8 |
| CrawlRequest(9) |  |

The `HalfBlock` message is used to share a block.
It is sent when a transaction is being made or upon a `CrawlRequest`.
Upon receipt, the TrustChain logic will determine if the block is valid and/or other blocks need to be crawled to validate the received block.
The `HalfBlock` message has the following attributes:

 - *public_key*: the key of the block owner
 - *sequence_number*: the sequence number of the block in the chain of the owner
 - *link_public_key*: the public key of the party with which the owner transacted
 - *link_sequence_number*: the sequence number of the block in the chain of the other party\*
 - *previous_hash*: the hash of the previous block in the owners chain
 - *signature*: the cryptographic signature of this block, using *public_key*
 - *transaction*: the binary blob containing the data portion of this block

\* NOTE: The *link_sequence_number* of the party requesting the transaction be signed is always 0.
The blocks are only linked by sequence number through the second "half" of the block.
Therefore, you should always use `get_linked()` of `database.py` to retrieve a block's other half.

## Block
The block class has a high overlap with the `HalfBlock` message.
The `TrustChainBlock` however, provides methods for validating (`validate()`), signing (`sign()`) and hashing (`hash`) blocks.

## Database
The database class is responsible for (1) storing and (2) querying blocks in the databsae, of both the owner and crawled third parties.
One can either access this datastructure as a linked list, or by index reference (sequence number).

For linked list type usage use:
 - `get_latest()` to get the last block for some peer
 - `get_latest_blocks()` to get the tail of the chain for some peer
 - `get_block_after()` to get the next block in a chain
 - `get_block_before()` to get the previous block in a chain
 - `get_linked()` to get the linked block from another chain (if available)

For indexed usage, one can use:
 - `get()` to get a specific block for a specific peer and manually read the `TrustChainBlock`
 
As previously mentioned, do bear in mind that the *link_sequence_number* will always be 0 for the transactor and non-zero for the transactee.
As such, *link_sequence_number* should never be used to perform a subsequent `get()`: `get_linked()` should be used instead.

## Community
The `TrustChainCommunity` class provides the higher order TrustChain logic.
In particular, it maintains a database object (`persistence`) and decides when to send `CrawlRequest` and `HalfBlock` messages to other peers.
This class implements the behavior as specified in the [Payload](#payload) section.
Additionally, this class also provides the interface for creating blocks: `sign_block()` and `should_sign()`.

**The `should_sign()` method should be defined in a subclass of `TrustChainCommunity` to define the buisiness logic for when to sign a block of another party.**

The `sign_block()` method is responsible for initiating a two-party signing of a block with another peer and is the main access point for block creation.

In short: use `sign_block()` to create blocks and use `should_sign()` to accept or reject blocks based on the transaction value.
Note that `should_sign()` does not have to validate the correctness of the chain (which is checked by the `TrustChainCommunity` class), only of the *transaction* content of the block.