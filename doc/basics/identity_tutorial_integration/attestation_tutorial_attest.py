import os
import shutil

from attestation_tutorial_common import finish, http_get, http_post, start, urlstr, wait_for_list

# Remove the output of previous experiments.
if os.path.exists('./state_1'):
    shutil.rmtree('./state_1')
if os.path.exists('./state_2'):
    shutil.rmtree('./state_2')

start()
print("Enrollment/Attestation flow")

print("0. SANITY CHECK")
http_get("http://localhost:14411/identity/pseudonym1/peers")
http_get("http://localhost:14412/identity/pseudonym2/peers")
peer1_neighborhood = wait_for_list("http://localhost:14411/identity/pseudonym1/peers", "peers")
peer2_neighborhood = wait_for_list("http://localhost:14412/identity/pseudonym2/peers", "peers")

peer1_id = urlstr(peer2_neighborhood[0])
peer2_id = urlstr(peer1_neighborhood[0])

print("Peer 1:", peer1_id)
print("Peer 2:", peer2_id)

print("Peer 1 attributes:", http_get("http://localhost:14411/identity/pseudonym1/credentials"))
print("Peer 2 attributes:", http_get("http://localhost:14412/identity/pseudonym2/credentials"))

print("1. ATTESTATION REQUEST")
print("Request attestation from peer 2:",
      http_post(f"http://localhost:14411/identity/pseudonym1/request/{peer2_id}",
                {"Content-Type": "application/json"},
                b'{"name":"my_attribute","schema":"id_metadata","metadata":{}}'))

print("2. ATTESTATION")
peer2_outstanding_requests = wait_for_list("http://localhost:14412/identity/pseudonym2/outstanding/attestations",
                                           "requests")
print("Peer 2 outstanding requests:", peer2_outstanding_requests)

print("Peer 2 attesting to outstanding request:",
      http_post(f"http://localhost:14412/identity/pseudonym2/attest/{peer1_id}",
                {"Content-Type": "application/json"},
                b'{"name":"my_attribute","value":"dmFsdWU="}'))

print("3. CHECK")
peer1_attributes = http_get("http://localhost:14411/identity/pseudonym1/credentials")
print("Peer 1 attributes:", peer1_attributes)
print("Peer 2 attributes:", http_get("http://localhost:14412/identity/pseudonym2/credentials"))

assert len(peer1_attributes['names']) > 0

print("X. DONE!")
finish()
