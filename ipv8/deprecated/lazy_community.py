from .payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from ..keyvault.crypto import ECCrypto
from ..overlay import Overlay
from ..peer import Peer


def lazy_wrapper(*payloads):
    """
    This function wrapper will unpack the BinMemberAuthenticationPayload for you.

    You can now write your authenticated and signed functions as follows:

    ::

        @lazy_wrapper(GlobalTimeDistributionPayload, IntroductionRequestPayload, IntroductionResponsePayload)
        def on_message(peer, payload1, payload2):
            '''
            :type peer: Peer
            :type payload1: IntroductionRequestPayload
            :type payload2: IntroductionResponsePayload
            '''
            pass
    """
    def decorator(func):
        def wrapper(self, source_address, data):
            # UNPACK
            auth, remainder = self.serializer.unpack_to_serializables([BinMemberAuthenticationPayload, ], data[23:])
            signature_valid, remainder = self._verify_signature(auth, data)
            unpacked = self.serializer.unpack_to_serializables(payloads, remainder[23:])
            output, unknown_data = unpacked[:-1], unpacked[-1]
            # ASSERT
            if len(unknown_data) != 0:
                raise PacketDecodingError("Incoming packet %s (%s) has extra data: (%s)" %
                                          (str([payload_class.__name__ for payload_class in payloads]),
                                           data.encode('HEX'),
                                           unknown_data.encode('HEX')))

            if not signature_valid:
                raise PacketDecodingError("Incoming packet %s has an invalid signature" % \
                                          str([payload_class.__name__ for payload_class in payloads]))
            # PRODUCE
            return func(self, Peer(auth.public_key_bin, source_address), *output)
        return wrapper
    return decorator


def lazy_wrapper_wd(*payloads):
    """
    This function wrapper will unpack the BinMemberAuthenticationPayload for you, as well as pass the raw data to the
    decorated function

    You can now write your authenticated and signed functions as follows:

    ::

        @lazy_wrapper(GlobalTimeDistributionPayload, IntroductionRequestPayload, IntroductionResponsePayload)
        def on_message(peer, payload1, payload2, data):
            '''
            :type peer: Peer
            :type payload1: IntroductionRequestPayload
            :type payload2: IntroductionResponsePayload
            '''
            pass
    """
    def decorator(func):
        def wrapper(self, source_address, data):
            # UNPACK
            auth, remainder = self.serializer.unpack_to_serializables([BinMemberAuthenticationPayload, ], data[23:])
            signature_valid, remainder = self._verify_signature(auth, data)
            unpacked = self.serializer.unpack_to_serializables(payloads, remainder[23:])
            output, unknown_data = unpacked[:-1], unpacked[-1]
            # ASSERT
            if len(unknown_data) != 0:
                raise PacketDecodingError("Incoming packet %s (%s) has extra data: (%s)" %
                                          (str([payload_class.__name__ for payload_class in payloads]),
                                           data.encode('HEX'),
                                           unknown_data.encode('HEX')))

            if not signature_valid:
                raise PacketDecodingError("Incoming packet %s has an invalid signature" % \
                                          str([payload_class.__name__ for payload_class in payloads]))
            # PRODUCE
            output = output + [data]
            return func(self, Peer(auth.public_key_bin, source_address), *output)
        return wrapper
    return decorator


def lazy_wrapper_unsigned(*payloads):
    """
    This function wrapper will unpack just the normal payloads for you.

    You can now write your non-authenticated and signed functions as follows:

    ::

        @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, IntroductionRequestPayload, IntroductionResponsePayload)
        def on_message(source_address, payload1, payload2):
            '''
            :type source_address: str
            :type payload1: IntroductionRequestPayload
            :type payload2: IntroductionResponsePayload
            '''
            pass
    """
    def decorator(func):
        def wrapper(self, source_address, data):
            # UNPACK
            unpacked = self.serializer.unpack_to_serializables(payloads, data[23:])
            output, unknown_data = unpacked[:-1], unpacked[-1]
            # ASSERT
            if len(unknown_data) != 0:
                raise PacketDecodingError("Incoming packet %s (%s) has extra data: (%s)" %
                                          (str([payload_class.__name__ for payload_class in payloads]),
                                           data.encode('HEX'),
                                           unknown_data.encode('HEX')))

            # PRODUCE
            return func(self, source_address, *output)
        return wrapper
    return decorator


def lazy_wrapper_unsigned_wd(*payloads):
    """
    This function wrapper will unpack just the normal payloads for you, as well as pass the raw data to the decorated
    function

    You can now write your non-authenticated and signed functions as follows:

    ::

        @lazy_wrapper_unsigned_wd(GlobalTimeDistributionPayload, IntroductionRequestPayload,
        IntroductionResponsePayload)
        def on_message(source_address, payload1, payload2, data):
            '''
            :type source_address: str
            :type payload1: IntroductionRequestPayload
            :type payload2: IntroductionResponsePayload
            '''
            pass
    """
    def decorator(func):
        def wrapper(self, source_address, data):

            @lazy_wrapper_unsigned(*payloads)
            def inner_wrapper(inner_self, inner_source_address, *pyls):
                combo = list(pyls) + [data]
                return func(inner_self, inner_source_address, *combo)

            return inner_wrapper(self, source_address, data)
        return wrapper
    return decorator


class EZPackOverlay(Overlay):

    def _ez_pack(self, prefix, msg_num, format_list_list, sig=True):
        packet = prefix + chr(msg_num)
        for format_list in format_list_list:
            packet += self.serializer.pack_multiple(format_list)[0]
        if sig:
            packet += ECCrypto().create_signature(self.my_peer.key, packet)
        return packet

    def _verify_signature(self, auth, data):
        ec = ECCrypto()
        public_key = ec.key_from_public_bin(auth.public_key_bin)
        signature_length = ec.get_signature_length(public_key)
        remainder = data[2 + len(auth.public_key_bin):-signature_length]
        signature = data[-signature_length:]
        return ec.is_valid_signature(public_key, data[:-signature_length], signature), remainder

    def _ez_unpack_auth(self, payload_class, data):
        # UNPACK
        auth, remainder = self.serializer.unpack_to_serializables([BinMemberAuthenticationPayload, ], data[23:])
        signature_valid, remainder = self._verify_signature(auth, data)
        format = [GlobalTimeDistributionPayload, payload_class]
        dist, payload, unknown_data = self.serializer.unpack_to_serializables(format, remainder[23:])
        # ASSERT
        if len(unknown_data) != 0:
            raise PacketDecodingError("Incoming packet %s (%s) has extra data: (%s)" %
                                      (payload_class.__name__,
                                       data.encode('HEX'),
                                       unknown_data.encode('HEX')))

        if not signature_valid:
            raise PacketDecodingError("Incoming packet %s has an invalid signature" % payload_class.__name__)
        # PRODUCE
        return auth, dist, payload

    def _ez_unpack_noauth(self, payload_class, data, global_time=True):
        # UNPACK
        format = [GlobalTimeDistributionPayload, payload_class] if global_time else [payload_class]
        unpacked = self.serializer.unpack_to_serializables(format, data[23:])
        unknown_data = unpacked.pop()
        # ASSERT
        if len(unknown_data) != 0:
            raise PacketDecodingError("Incoming packet %s (%s) has extra data: (%s)" %
                                      (payload_class.__name__,
                                       data.encode('HEX'),
                                       unknown_data.encode('HEX')))
        # PRODUCE
        return unpacked if global_time else unpacked[0]


class PacketDecodingError(RuntimeError):
    pass
