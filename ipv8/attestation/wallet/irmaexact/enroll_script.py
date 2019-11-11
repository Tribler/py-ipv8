import base64
import binascii
import json
import sys
import time

from PyQt5.QtCore import *
from PyQt5.QtWebEngineWidgets import *
from PyQt5.QtWidgets import QApplication

import urllib3

from . import secure_randint
from .gabi.attributes import make_attribute_list
from .gabi.builder import BuildDistributedProofList, Challenge, CredentialBuilder, IssueCommitmentMessage, IssueSignatureMessage
from .gabi.keys import CLSignature, DefaultSystemParameters
from .gabi.proofs import ProofP, ProofPCommitment, ProofS
from .keydump import nijmegen_pk_1568208470 as nijmegen_pk
from .wrappers import serialize_proof_d
from ...util import int2byte

my_app = QApplication(sys.argv)
my_web = QWebEngineView()
token = None


def print_result(r):
    global token
    if r:
        u = json.loads(r)["u"].encode('utf-8')
        token = u.split('/')[-1]
        my_web.hide()
        my_app.quit()


def page_loaded(ok):
    if ok and my_web.url() == QUrl(u'https://services.nijmegen.nl/irma/issue?'):
        my_web.page().runJavaScript("document.getElementById(\"qrcode\").title", print_result)


my_web.loadFinished.connect(page_loaded)
my_web.load(QUrl("https://services.nijmegen.nl/irma/issue"))
my_web.setWindowTitle("Annoying Pop-up")
my_web.show()

my_app.exec_()

secret = secure_randint(DefaultSystemParameters[1024].Lm)

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
u = do_post(u, "{\"username\":\"\",\"pin\":\"%s\",\"email\":null,\"language\":\"en\"}" % no_pin)[u'u']
response = do_get(u)
context = int(binascii.hexlify(base64.b64decode(response[u"context"])), 16)
nonce = int(binascii.hexlify(base64.b64decode(response[u"nonce"])), 16)
irmaid = response[u"credentials"][0][u"attributes"][u"email"]
u = "https://keyshare.privacybydesign.foundation/tomcat/irma_keyshare_server/api/v1/users/verify/pin"
jwt = do_post(u, "{\"id\":\"%s\",\"pin\":\"%s\"}" % (irmaid, no_pin))[u"message"]
extra_headers = {"Authorization": jwt, "X-IRMA-Keyshare-Username": ""}
u = "https://keyshare.privacybydesign.foundation/tomcat/irma_keyshare_server/api/v1/prove/getCommitments"
response = do_post(u, "[{\"issuer\":{\"identifier\":\"pbdf.nijmegen\"},\"counter\": 0},{\"issuer\":{\"identifier\":\"pbdf.nijmegen\"},\"counter\": 0},{\"issuer\":{\"identifier\":\"pbdf.nijmegen\"},\"counter\": 0},{\"issuer\":{\"identifier\":\"pbdf.nijmegen\"},\"counter\": 0}]", extra_headers=extra_headers)
Pcommit = response[u'c'][0][1][u'Pcommit']
P = response[u'c'][0][1][u'P']

# Get nijmegen issuance
u = 'https://www.nijmegen.nl/personen/attributen/irma-server-api/api/v2/issue/%s' % token
issuance_output = do_get(u)
context = int(binascii.hexlify(base64.b64decode(issuance_output[u'context'])), 16)
nonce1 = int(binascii.hexlify(base64.b64decode(issuance_output[u'nonce'])), 16)

u = "https://keyshare.privacybydesign.foundation/tomcat/irma_keyshare_server/api/v1/prove/getResponse"
cbs = [CredentialBuilder(nijmegen_pk, context, secret, nonce1) for _ in range(4)]
for cb in cbs:
    cb.MergeProofPCommitment(ProofPCommitment(P, Pcommit))
challenge = Challenge(cbs, context, nonce1, False)
commit_jwt = do_post(u, str(challenge), extra_headers=extra_headers)
proofP_d = commit_jwt.split('.')[1]
lens = len(proofP_d)
lenx = lens - (lens % 4 if lens % 4 else 4)
proofP_d = json.loads(base64.decodestring(proofP_d[:lenx]) + '}')[u"ProofP"]
P = proofP_d[u"P"]
c = proofP_d[u"c"]
s_response = proofP_d[u"s_response"]
proofP = ProofP(P, c, s_response)

u = 'https://www.nijmegen.nl/personen/attributen/irma-server-api/api/v2/issue/%s/status' % token

while do_get(u) != "CONNECTED":
    time.sleep(0.5)

u = 'https://www.nijmegen.nl/personen/attributen/irma-server-api/api/v2/issue/%s/commitments' % token

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
outjson += '"proofPJwts": {"pbdf": "' + commit_jwt + '"}'
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
    proof_s_desc = ism[u"proof"]
    sig_desc = ism[u"signature"]
    proof_s = ProofS(b64_to_int(proof_s_desc[u"c"]), b64_to_int(proof_s_desc[u"e_response"]))
    signature = CLSignature(b64_to_int(sig_desc[u"A"]), b64_to_int(sig_desc[u"e"]), b64_to_int(sig_desc[u"v"]))
    isms.append(IssueSignatureMessage(signature, proof_s))


order_map = {
    u'pbdf.nijmegen.address': [u"street", u"houseNumber", u"zipcode", u"municipality", u"city"],
    u'pbdf.nijmegen.personalData': [u"initials", u"firstnames", u"prefix", u"familyname", u"surname",
                                    u"fullname", u"dateofbirth", u"gender", u"nationality"],
    u'pbdf.nijmegen.ageLimits': [u"over12", u"over16", u"over18", u"over21", u"over65"],
    u'pbdf.nijmegen.bsn': [u"bsn"]
}


for i in range(len(cbs)):
    cb = cbs[i]
    ism = isms[i]
    ordering = order_map[issuance_output[u"credentials"][i][u'credential']]
    attribute_ints, signing_date = make_attribute_list(issuance_output[u"credentials"][i], ordering)

    credential = cb.ConstructCredential(ism, attribute_ints)
    builder = credential.CreateDisclosureProofBuilder(list(range(1, len(attribute_ints) + 1)))
    builder.MergeProofPCommitment(ProofPCommitment(P, Pcommit))
    commit_randomizer = secure_randint(nijmegen_pk.Params.LmCommit)
    A, Z = builder.Commit(commit_randomizer)
    p = builder.CreateProof(challenge)
    p.MergeProofP(proofP, nijmegen_pk)

    attr_output = '{\n'
    attr_output += '\t"sign_date": ' + str(signing_date) + ',\n'
    attr_output += '\t"proofd": "' + binascii.hexlify(serialize_proof_d(p)) + '",\n'
    attr_output += '\t"z": ' + str(Z) + '\n'
    attr_output += '}'

    print("*" * 20)
    print("Attribute:", issuance_output[u"credentials"][i][u'credential'])
    print(attr_output)
    print("*" * 20)
