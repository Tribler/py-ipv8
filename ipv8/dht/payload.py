from socket import inet_aton, inet_ntoa
from struct import pack, unpack_from

from .routing import Node
from ..messaging.lazy_payload import VariablePayload, vp_compile


@vp_compile
class PingRequestPayload(VariablePayload):
    msg_id = 1
    names = ['identifier']
    format_list = ['I']


@vp_compile
class PingResponsePayload(VariablePayload):
    msg_id = 2
    names = ['identifier']
    format_list = ['I']


@vp_compile
class StoreRequestPayload(VariablePayload):
    msg_id = 3
    names = ['identifier', 'token', 'target', 'values']
    format_list = ['I', '20s', '20s', 'varlenH-list']


@vp_compile
class StoreResponsePayload(VariablePayload):
    msg_id = 4
    names = ['identifier']
    format_list = ['I']


@vp_compile
class FindRequestPayload(VariablePayload):
    msg_id = 5
    names = ['identifier', 'lan_address', 'target', 'offset', 'force_nodes']
    format_list = ['I', 'ipv4', '20s', 'I', '?']


@vp_compile
class FindResponsePayload(VariablePayload):
    msg_id = 6
    names = ['identifier', 'token', 'values', 'nodes']
    format_list = ['I', '20s', 'varlenH-list', 'node-list']


@vp_compile
class StorePeerRequestPayload(VariablePayload):
    msg_id = 7
    names = ['identifier', 'token', 'target']
    format_list = ['I', '20s', '20s']


@vp_compile
class StorePeerResponsePayload(VariablePayload):
    msg_id = 8
    names = ['identifier']
    format_list = ['I']


@vp_compile
class ConnectPeerRequestPayload(VariablePayload):
    msg_id = 9
    names = ['identifier', 'lan_address', 'target']
    format_list = ['I', 'ipv4', '20s']


@vp_compile
class ConnectPeerResponsePayload(VariablePayload):
    msg_id = 10
    names = ['identifier', 'nodes']
    format_list = ['I', 'node-list']


@vp_compile
class StrPayload(VariablePayload):
    names = ['data']
    format_list = ['raw']


@vp_compile
class SignedStrPayload(VariablePayload):
    names = ['data', 'version', 'public_key']
    format_list = ['varlenH', 'I', 'varlenH']


class NodePacker:

    def pack(self, node):
        key = node.public_key.key_to_bin()
        return pack('>4sHH', inet_aton(node.address[0]), node.address[1], len(key)) + key

    def unpack(self, data, offset, unpack_list):
        ip, port, key_length = unpack_from('>4sHH', data, offset)
        offset += 8
        unpack_list.append(Node(data[offset:offset + key_length], address=(inet_ntoa(ip), port)))
        return offset + key_length
