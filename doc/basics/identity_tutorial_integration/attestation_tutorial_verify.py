from attestation_tutorial_common import finish, http_get, http_post, start, urlstr, wait_for_list

start()
print("Attribute verification flow")

print("0. SANITY CHECK")
http_get("http://localhost:14411/identity/pseudonym1/peers")
http_get("http://localhost:14412/identity/pseudonym2/peers")
peer1_neighborhood = wait_for_list("http://localhost:14411/identity/pseudonym1/peers", "peers")
peer2_neighborhood = wait_for_list("http://localhost:14412/identity/pseudonym2/peers", "peers")

peer1_id = urlstr(peer2_neighborhood[0])
peer2_id = urlstr(peer1_neighborhood[0])

print("Peer 1:", peer1_id)
print("Peer 2:", peer2_id)

peer1_attributes = http_get("http://localhost:14411/identity/pseudonym1/credentials")['names']
peer2_attributes = http_get("http://localhost:14412/identity/pseudonym2/credentials")['names']

print("Peer 1 attributes:", peer1_attributes)
print("Peer 2 attributes:", peer2_attributes)

attribute_hash = peer1_attributes[-1]["hash"].encode()

print("1. VERIFICATION REQUEST")
print("Request verification from peer 1:",
      http_post(f"http://localhost:14412/identity/pseudonym2/verify/{peer1_id}",
                {"Content-Type": "application/json"},
                b'{"hash":"' + attribute_hash + b'","value":"dmFsdWU=","schema":"id_metadata"}'))

print("2. VERIFICATION ")
peer1_outstanding_requests = wait_for_list("http://localhost:14411/identity/pseudonym1/outstanding/verifications",
                                           "requests")
print("Peer 1 outstanding verification requests:", peer1_outstanding_requests)

print("Peer 1 allow verification of outstanding request:",
      http_post(f"http://localhost:14411/identity/pseudonym1/allow/{peer2_id}",
                {"Content-Type": "application/json"},
                b'{"name":"my_attribute"}'))

print("3. CHECK")
verification_output = wait_for_list("http://localhost:14412/identity/pseudonym2/verifications", 'outputs')
print("Peer 2 verification output:", )
assert verification_output[0]['match'] > 0.9

print("X. DONE!")
finish()
