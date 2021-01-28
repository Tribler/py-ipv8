
Peer discovery basics
=====================
All IPv8 overlays have 4 messages in common: introduction-request, introduction-response, puncture-request, and puncture. These 4 messages are used for peer discovery and NAT puncturing.

The peer discovery protocol runs the following steps in a loop until enough peers have been found:

1. Peer A sends an introduction-request to peer B. Peer B is chosen from an existing pool of neighboring peers.
2. Peer B sends an introduction-response to peer A containing the address of peer C.
3. Peer B sends a puncture-request to peer C containing the address of peer A.
4. Peer C sends a puncture to peer A, puncturing its NAT.

 .. image:: ./resources/ipv8_peer_discovery.png
   :target: ./resources/ipv8_peer_discovery.png
   :alt: The IPv8 peer discovery protocol
   :align: center
 
When a peer doesn't yet have a list of neighboring peers, it will select a bootstrap server for peer B. IPv8 bootstrap servers implement the same peer discovery protocol as ordinary peers, except that they respond to introduction-requests for *any* overlay. Once a peer sends an introduction-request to a bootstrap server, the bootstrap server will keep track of the sender and the overlay within which the introduction-request was sent. When sending introduction-responses, the bootstrap server will pick a peer from this list as an introduction candidate (peer C in the image above).
Periodically, the bootstrap server will send an introduction-request for a random peer in the list. If the peer doesn't respond with an introduction-response, the bootstrap server will assume that the unresponsive peer is no longer interested in new peers and update its list accordingly.
