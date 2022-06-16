
Advanced peer discovery configuration
=====================================

This document assumes you have a basic understanding of peer discovery in IPv8, as documented in `the peer discovery basics <../reference/peer_discovery.html>`_.
This document covers the configuration of built-in ``DiscoveryStrategy`` classes, explained in `the network IO and the DiscoveryStrategy tutorial <../basics/discoverystrategy_tutorial.html>`_.
In particular, we address the following three topics:

- How the ``RandomWalk`` works and when to use it.
- How the ``EdgeWalk`` works and when to use it.
- How to parameterize the walk strategies in relation to the overlays they operate on.
- How the ``RandomChurn`` works and when to use it.

The Random walk strategy
------------------------

The "Random" walk strategy finds new peers by randomly querying existing peers.
Every IPv8 tick a random peer is chosen from the overlay that a ``RandomWalk`` class is attached to.
The chosen peer is then asked for new peers (using the introduction-request mechanism), to which it responds with a random peer that it knows.
In case a random peer knows no other peers, it responds with no peer.
In the case that no peers are available to ask for introductions, the bootstrap mechanism is invoked.

The most important aspect of the "Random" walk strategy is that **it is not a search strategy**.
Because there is no attempt to avoid previously queried peers, the mechanism is very simple.
However, a previously queried peer that has no new available connections is not avoided, making the "Random" walk waste bandwidth if there are no further peers to find.
Secondly, if a strong clique forms in the connection graph it can take very long to find new peers if networks get large.
Nevertheless, the strategy **is robust against networks with high node churn**.
For the purposes of IPv8 connections the "Random" strategy is usually the preferred strategy as the number of connected peers remains relatively low.

The Edge walk strategy
----------------------

The "Edge" walk strategy is another strategy to find new peers based on existing peers.
However, unlike the "Random" strategy, the "Edge" strategy is a search strategy.
The "Edge" strategy uses a depth-first search through known peers.
Each edge of a search starts at a peer found by the bootstrap process.
Peers are then queried in order of introduction for a random peer they are connected to.
After a configured search depth has been reached, a new edge is constructed.

The "Edge" walk is typically used to find as many peers as possible at the cost of additional overhead.
Peers are not often revisited and therefore this strategy is bandwidth efficient.
Of course, managing the edges means that there is more computational overhead in managing peers.
Finding many peers is rarely preferential for "normal" IPv8 use, but it can be useful when creating network crawlers.

Parameterizing walk strategies
------------------------------

For every walk strategy IPv8 maintains a number of target peers and for every overlay IPv8 a number of maximum peers.
The former tells IPv8 to keep calling the walker until a certain number of peers has been accepted and the latter tells IPv8 when to stop accepting new connections.
**You should never ever configure the walk strategies to fill out an overlay's maximum peers.**
By doing so, you can inadvertently create network partitions.

The default settings, of ``20`` target peers for the walk and ``30`` maximum connections for the overlay, are tried and tested.
More connections do not imply a better overlay and may, in fact, prove detrimental.
For example, connecting to ``1000`` peers may completely overload a machine's buffers and drop most of the incoming UDP packets.
There are three main points to remember.
Firstly, it is generally better to depend on a good information dissemination strategy than on a large number of connections.
Secondly, the number of connections you open has diminishing returns for the speed at which information makes its way through your network.
Finally, the more connections you open, the higher the chance that attackers come into connection with a peer.

It is a good idea to first run extensive experiments before changing walk parameterization.
Finding peers is complex because it is (a) a process that uses asynchronous messaging, (b) the connection graph between peers is highly dynamic, and (c) peers may not have the same parameterization.

If you do decide to change the parameterization, do not mix overlays with different parameterizations.
Sampling from a set with replacement is a statistical process.
IPv8 does not come with a built-in mechanism to balance out the sampling rate according to differences in set sizes (i.e., the number of peers in each overlay).
If you do have different walk parameterizations, ``max_peers``, or ``target_peers``, make sure to give each overlay a separate ``Network`` instance.

The RandomChurn churn strategy
------------------------------

The "Random" churn strategy is a strategy to remove unresponsive peers from overlays.
Peers are randomly sampled and if they have not been communicated with in the last thirty seconds, they will be pinged for a response.
If a peer does not respond to a ping request, it will be removed from the ``Network``.

If you have a shared ``Network`` instance, you only need to apply the ``RandomChurn`` to a single overlay.
However, be cautioned that you need a ``RandomChurn`` for each ``Network`` instance.

By default the ``RandomChurn`` strategy checks eight peers simultaneously.
A total three pings are sent, one every ten seconds, after 30 seconds of inactivity.
These settings should be adjusted if a large number of peers are being connected to.
