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
peer1_neighborhood = wait_for_list("http://localhost:14411/attestation?type=peers")
peer2_neighborhood = wait_for_list("http://localhost:14412/attestation?type=peers")

peer1_id = urlstr(peer2_neighborhood[0])
peer2_id = urlstr(peer1_neighborhood[0])

print("Peer 1:", peer1_id)
print("Peer 2:", peer2_id)

print("Peer 1 attributes:", http_get("http://localhost:14411/attestation?type=attributes"))
print("Peer 2 attributes:", http_get("http://localhost:14412/attestation?type=attributes"))

print("1. ATTESTATION REQUEST")
print("Request attestation from peer 2:",
      http_post(f"http://localhost:14411/attestation?type=request&mid={peer2_id}&attribute_name=my_attribute"))

print("2. ATTESTATION")
peer2_outstanding_requests = wait_for_list("http://localhost:14412/attestation?type=outstanding")
print("Peer 2 outstanding requests:", peer2_outstanding_requests)

print("Peer 2 attesting to outstanding request:",
      http_post(f"http://localhost:14412/attestation?type=attest&mid={peer1_id}"
                f"&attribute_name={peer2_outstanding_requests[0][1]}"
                f"&attribute_value=dmFsdWU%3D"))

print("3. CHECK")
peer1_attributes = http_get("http://localhost:14411/attestation?type=attributes")
print("Peer 1 attributes:", peer1_attributes)
print("Peer 2 attributes:", http_get("http://localhost:14412/attestation?type=attributes"))

assert len(peer1_attributes) > 0

print("X. DONE!")
finish()
