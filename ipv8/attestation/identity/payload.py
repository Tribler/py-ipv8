from ...messaging.lazy_payload import VariablePayloadWID, vp_compile


@vp_compile
class DiclosePayload(VariablePayloadWID):
    """
    A payload used for disclosure of identity meta information.
    """

    msg_id = 1
    format_list = ['varlenH', 'varlenH', 'varlenH', 'varlenH']
    names = ['metadata', 'tokens', 'attestations', 'authorities']

    metadata: bytes
    tokens: bytes
    attestations: bytes
    authorities: bytes


@vp_compile
class AttestPayload(VariablePayloadWID):
    """
    A payload used for attestation.
    """

    msg_id = 2
    format_list = ['varlenH']
    names = ['attestation']

    attestation: bytes


@vp_compile
class RequestMissingPayload(VariablePayloadWID):
    """
    A payload used to request missing identity meta information.
    """

    msg_id = 3
    format_list = ['I']
    names = ['known']

    known: int


@vp_compile
class MissingResponsePayload(VariablePayloadWID):
    """
    A payload to respond with missing identity meta information.
    """

    msg_id = 4
    format_list = ['raw']
    names = ['tokens']

    tokens: bytes
