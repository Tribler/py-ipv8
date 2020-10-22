from ...messaging.lazy_payload import VariablePayload, vp_compile


@vp_compile
class DiclosePayload(VariablePayload):
    msg_id = 1
    format_list = ['varlenH', 'varlenH', 'varlenH', 'varlenH']
    names = ['metadata', 'tokens', 'attestations', 'authorities']

    metadata: bytes
    tokens: bytes
    attestations: bytes
    authorities: bytes


@vp_compile
class AttestPayload(VariablePayload):
    msg_id = 2
    format_list = ['varlenH']
    names = ['attestation']

    attestation: bytes


@vp_compile
class RequestMissingPayload(VariablePayload):
    msg_id = 3
    format_list = ['I']
    names = ['known']

    known: int


@vp_compile
class MissingResponsePayload(VariablePayload):
    msg_id = 4
    format_list = ['raw']
    names = ['tokens']

    tokens: bytes
