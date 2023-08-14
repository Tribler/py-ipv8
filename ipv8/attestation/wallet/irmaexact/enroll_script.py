"""
Additional dependencies:

python3 -m pip install PyQtWebEngine

To run:
export PYTHONPATH=.
python3 -m ipv8.attestation.wallet.irmaexact.enroll_script
"""

# ruff: noqa

import base64
import binascii
import json
import sys
import time

from PyQt5.QtCore import *
from PyQt5.QtWebEngineWidgets import *
from PyQt5.QtWidgets import QApplication

import urllib3

from .gabi.attributes import make_attribute_list
from .gabi.builder import BuildDistributedProofList, Challenge, CredentialBuilder, IssueCommitmentMessage, IssueSignatureMessage
from .gabi.keys import CLSignature, DefaultSystemParameters
from .gabi.proofs import ProofP, ProofPCommitment, ProofS
from .keydump import nijmegen_pk_1623505755 as nijmegen_pk
from .wrappers import serialize_proof_d
from ..primitives.cryptography_wrapper import generate_safe_prime
from ....util import int2byte

my_app = QApplication(sys.argv)
my_web = QWebEngineView()
profile = QWebEngineProfile("storage", my_web)
cookie_store = profile.cookieStore()
cookie_store.deleteAllCookies()

token = None


def print_result(r):
    global token
    if r:
        u = json.loads(r)["u"].encode()
        token = u.split(b'/')[-1].decode()
        my_web.hide()
        my_app.quit()


def page_loaded(ok):
    if ok and my_web.url() == QUrl('https://services.nijmegen.nl/irma/gemeente/issue?'):
        my_web.page().runJavaScript("window.irmaSessionPtr", print_result)


my_web.loadFinished.connect(page_loaded)
my_web.load(QUrl("https://services.nijmegen.nl/irma/gemeente/issue"))
my_web.setWindowTitle("Annoying Pop-up")
my_web.show()

my_app.exec_()

secret = generate_safe_prime(DefaultSystemParameters[1024].Lm)

no_pin = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\\n'


def do_get(u):
    http = urllib3.PoolManager()
    headers = {'Content-Type': 'application/json',
               "X-IRMA-MinProtocolVersion": "2.4",
               "X-IRMA-MaxProtocolVersion": "2.4"}

    r = http.request('GET', u, headers=headers)
    try:
        out = json.loads(r.data)
    except ValueError:
        out = r.data

    return out


def do_post(u, content, extra_headers={}):
    http = urllib3.PoolManager()
    headers = {'Content-Type': 'application/json'}
    headers.update(extra_headers)

    r = http.request('POST', u, headers=headers, body=content)
    try:
        out = json.loads(r.data)
    except ValueError:
        out = r.data

    return out


u = "https://keyshare.privacybydesign.foundation/tomcat/irma_keyshare_server/api/v1/client/register"
u = do_post(u, "{\"username\":\"\",\"pin\":\"%s\",\"email\":null,\"language\":\"en\"}" % no_pin)['u']
response = do_get(u)
context = int(binascii.hexlify(base64.b64decode(response["context"])), 16)
nonce = int(binascii.hexlify(base64.b64decode(response["nonce"])), 16)

irmaid = response["credentials"][0]["attributes"]["pseudonym"]
u = "https://keyshare.privacybydesign.foundation/tomcat/irma_keyshare_server/api/v1/users/verify/pin"
jwt = do_post(u, f"{{\"id\":\"{irmaid}\",\"pin\":\"{no_pin}\"}}")["message"]

extra_headers = {"Authorization": jwt, "X-IRMA-Keyshare-Username": ""}
u = "https://keyshare.privacybydesign.foundation/tomcat/irma_keyshare_server/api/v1/prove/getCommitments"
response = do_post(u, "["
                      "{\"issuer\":{\"identifier\":\"pbdf.gemeente\"},\"counter\": 1},"
                      "{\"issuer\":{\"identifier\":\"pbdf.gemeente\"},\"counter\": 1}"
                      "]", extra_headers=extra_headers)
Pcommit = response['c'][0][1]['Pcommit']
P = response['c'][0][1]['P']

# Get nijmegen issuance
u = 'https://gw.nijmegen.nl/irma/session/%s/' % token
issuance_output = do_get(u)
context = int(binascii.hexlify(base64.b64decode(issuance_output['context'])), 16)
nonce1 = int(binascii.hexlify(base64.b64decode(issuance_output['nonce'])), 16)

u = "https://keyshare.privacybydesign.foundation/tomcat/irma_keyshare_server/api/v1/prove/getResponse"
# 2 because: 'pbdf.gemeente.address' and 'pbdf.gemeente.personalData'
cbs = [CredentialBuilder(nijmegen_pk, context, secret, nonce1) for _ in range(2)]
for cb in cbs:
    cb.MergeProofPCommitment(ProofPCommitment(P, Pcommit))
challenge = Challenge(cbs, context, nonce1, False)
commit_jwt = do_post(u, str(challenge), extra_headers=extra_headers)

proofP_d = commit_jwt.split(b'.')[1]
lens = len(proofP_d)
lenx = lens - (lens % 4 if lens % 4 else 4)
proofP_d = json.loads(base64.decodebytes(proofP_d[:lenx]) + b'}')["ProofP"]
P = proofP_d["P"]
c = proofP_d["c"]
s_response = proofP_d["s_response"]
proofP = ProofP(P, c, s_response)

u = 'https://gw.nijmegen.nl/irma/session/%s/status' % token

while do_get(u) != "CONNECTED":
    time.sleep(0.5)

u = 'https://gw.nijmegen.nl/irma/session/%s/commitments' % token

proofs = BuildDistributedProofList(cbs, challenge, [])
commitMsg = IssueCommitmentMessage(None, proofs, nonce1)


def proof_to_str(proof):
    return ('{"U": ' + str(proof.U)
            + ', "c": ' + str(proof.C)
            + ', "v_prime_response": ' + str(proof.VPrimeResponse)
            + ', "s_response": ' + str(proof.SResponse) + '}')


outjson = '{'
outjson += '"U": null,'
outjson += '"combinedProofs": [' + ', '.join(proof_to_str(p) for p in commitMsg.Proofs) + '],'
outjson += '"indices": [],'
outjson += '"n_2": ' + str(commitMsg.Nonce2) + ","
outjson += '"proofPJwt": "",'
outjson += '"proofPJwts": {"pbdf": "' + commit_jwt.decode() + '"}'
outjson += '}'

output_proof = do_post(u, outjson)


def b64_to_int(s):
    return str_to_int(base64.b64decode(s))


def str_to_int(s):
    if isinstance(s, str):
        s = b''.join(int2byte(ord(c)) for c in s)
    if s is None:
        return 0
    if s == b"":
        return 1
    return int(binascii.hexlify(s), 16)


isms = []
for ism in output_proof:
    proof_s_desc = ism["proof"]
    sig_desc = ism["signature"]
    proof_s = ProofS(b64_to_int(proof_s_desc["c"]), b64_to_int(proof_s_desc["e_response"]))
    signature = CLSignature(b64_to_int(sig_desc["A"]), b64_to_int(sig_desc["e"]), b64_to_int(sig_desc["v"]))
    isms.append(IssueSignatureMessage(signature, proof_s))


order_map = {
    'pbdf.gemeente.address': ["street", "houseNumber", "zipcode", "municipality", "city"],
    'pbdf.gemeente.personalData': ["initials", "firstnames", "prefix", "familyname", "fullname", "gender",
                                   "nationality", "surname", "dateofbirth", "cityofbirth", "countryofbirth", "over12",
                                   "over16", "over18", "over21", "over65", "bsn", "digidlevel"]
}


for i in range(len(cbs)):
    cb = cbs[i]
    ism = isms[i]
    ordering = order_map[issuance_output["credentials"][i]['credential']]
    attribute_ints, signing_date = make_attribute_list(issuance_output["credentials"][i], ordering)

    credential = cb.ConstructCredential(ism, attribute_ints)
    builder = credential.CreateDisclosureProofBuilder(list(range(1, len(attribute_ints) + 1)))
    builder.MergeProofPCommitment(ProofPCommitment(P, Pcommit))
    commit_randomizer = generate_safe_prime(nijmegen_pk.Params.LmCommit)
    A, Z = builder.Commit(commit_randomizer)
    p = builder.CreateProof(challenge)
    p.MergeProofP(proofP, nijmegen_pk)

    attr_output = '{\n'
    attr_output += '\t"sign_date": ' + str(signing_date) + ',\n'
    attr_output += '\t"proofd": "' + binascii.hexlify(serialize_proof_d(p)).decode() + '",\n'
    attr_output += '\t"z": ' + str(Z) + '\n'
    attr_output += '}'

    print("*" * 20)  # noqa: T201
    print("Attribute:", issuance_output["credentials"][i]['credential'])  # noqa: T201
    print(attr_output)  # noqa: T201
    print("*" * 20)  # noqa: T201
