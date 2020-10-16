import time

from attestation_tutorial_common import finish, http_get, http_post, start, urlstr, wait_for_list

start()
print("Attribute verification flow")

print("0. SANITY CHECK")
peer1_neighborhood = wait_for_list("http://localhost:14411/attestation?type=peers")
peer2_neighborhood = wait_for_list("http://localhost:14412/attestation?type=peers")

peer1_id = urlstr(peer2_neighborhood[0])
peer2_id = urlstr(peer1_neighborhood[0])

print("Peer 1:", peer1_id)
print("Peer 2:", peer2_id)

peer1_attributes = http_get("http://localhost:14411/attestation?type=attributes")
peer2_attributes = http_get("http://localhost:14412/attestation?type=attributes")

print("Peer 1 attributes:", peer1_attributes)
print("Peer 2 attributes:", peer2_attributes)

print("1. VERIFICATION REQUEST")
print("Request verification from peer 1:",
      http_post(f"http://localhost:14412/attestation?type=verify&mid={peer1_id}"
                f"&attribute_hash={urlstr(peer1_attributes[-1][1])}&attribute_values=dmFsdWU%3D"))

print("2. VERIFICATION ")
peer1_outstanding_requests = wait_for_list("http://localhost:14411/attestation?type=outstanding_verify")
print("Peer 1 outstanding verification requests:", peer1_outstanding_requests)

print("Peer 1 allow verification of outstanding request:",
      http_post(f"http://localhost:14411/attestation?type=allow_verify&mid={peer2_id}"
                f"&attribute_name={urlstr(peer1_attributes[-1][0])}"))

print("3. CHECK")
match = 0.0
while match < 0.9:
    for attribute_hash, output in http_get("http://localhost:14412/attestation?type=verification_output").items():
        if attribute_hash == peer1_attributes[-1][1]:
            match_value, match = output[0]
            assert match_value == "dmFsdWU="
    time.sleep(0.1)
print("Peer 2 verification output:", http_get("http://localhost:14412/attestation?type=verification_output"))

print("X. DONE!")
finish()
