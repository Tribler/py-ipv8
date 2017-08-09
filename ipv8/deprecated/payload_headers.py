from .payload import Payload


class BinMemberAuthenticationPayload(Payload):

    format_list = ['varlenH', ]

    def __init__(self, public_key_bin):
        super(BinMemberAuthenticationPayload, self).__init__()
        self.public_key_bin = public_key_bin

    def to_pack_list(self):
        return [('varlenH', self.public_key_bin)]

    @classmethod
    def from_unpack_list(cls, public_key_bin):
        return BinMemberAuthenticationPayload(public_key_bin)


class GlobalTimeDistributionPayload(Payload):

    format_list = ['Q', ]

    def __init__(self, global_time):
        super(GlobalTimeDistributionPayload, self).__init__()
        self.global_time = global_time

    def to_pack_list(self):
        return [('Q', self.global_time)]

    @classmethod
    def from_unpack_list(cls, global_time):
        return GlobalTimeDistributionPayload(global_time)


class SequencedGlobalTimeDistributionPayload(Payload):

    format_list = ['QL', ]

    def __init__(self, global_time, sequence_number):
        super(SequencedGlobalTimeDistributionPayload, self).__init__()
        self.global_time = global_time
        self.sequence_number = sequence_number

    def to_pack_list(self):
        return [('QL', self.global_time, self.sequence_number)]

    @classmethod
    def from_unpack_list(cls, global_time, sequence_number):
        return SequencedGlobalTimeDistributionPayload(global_time, sequence_number)
