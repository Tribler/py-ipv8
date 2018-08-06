import random
import string

from ipv8.deprecated.payload import Payload


class XDRPayload(Payload):
    """
    Payload with some random data
    """

    format_list = ['XDR_s', 'XDR_I', 'XDR_f'] * 5

    def to_pack_list(self):
        data = []
        for _ in xrange(0, 5):
            rand_len = random.randint(1, 20)
            rand_str = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(rand_len))
            data.append(('XDR_s', rand_str))
            data.append(('XDR_I', 1))
            data.append(('XDR_f', 1.1))

        return data

    @classmethod
    def from_unpack_list(cls, *data):
        return XDRPayload()


class NormalPayload(Payload):
    format_list = ['varlenI', 'I', 'f'] * 5

    def to_pack_list(self):
        data = []
        for _ in xrange(0, 5):
            rand_len = random.randint(1, 20)
            rand_str = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(rand_len))
            data.append(('varlenI', rand_str))
            data.append(('I', 1))
            data.append(('f', 1.1))

        return data

    @classmethod
    def from_unpack_list(cls, *data):
        return NormalPayload()
