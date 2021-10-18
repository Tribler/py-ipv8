from abc import ABC, abstractmethod
from functools import wraps
from typing import Iterable, List, Tuple, Type, Union

from .keyvault.crypto import default_eccrypto
from .messaging.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from .overlay import Overlay
from .peer import Peer
from .types import Address, AnyPayload, AnyPayloadType, NumberCache


def cache_retrieval_failed(overlay: Overlay, cache_class: Type[NumberCache]) -> None:
    """
    Handler for messages which failed to match to an existing overlay cache.
    """
    overlay.logger.debug("Failed to match %s: was answered late or did not exist.", repr(cache_class))


def retrieve_cache(cache_class: Type[NumberCache]):
    """
    This function wrapper match a payload to a registered cache for you.

    For this wrapper to function, you will need to comply with three standards:

     - The last specified payload must include an ``identifier`` attribute.
     - The ``cache_class`` must specify a ``name`` attribute.
     - The overlay this method belongs to has a ``request_cache`` attribute.

    You can now message handlers as follows:

    ::

        @lazy_wrapper(MyPayload1, MyPayload2)  # MyPayload2.identifier must exist!
        @retrieve_cache(MyCache)  # MyCache.name must exist!
        def on_message(peer: Peer,
                       payload1: MyPayload1,
                       payload2: MyPayload2,
                       cache: NumberCache):
            pass

    :param cache_class: the cache to fetch.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(self, peer_or_addr, *payloads):
            try:
                # For the ``_wd`` decorators, the last argument is the data and not the Payload.
                payload = payloads[-2 if isinstance(payloads[-1], bytes) else -1]
                cache = self.request_cache.pop(cache_class.name, payload.identifier)
                return func(self, peer_or_addr, *payloads, cache=cache)
            except KeyError:
                return cache_retrieval_failed(self, cache_class)

        return wrapper

    return decorator


def lazy_wrapper(*payloads: AnyPayloadType):
    """
    This function wrapper will unpack the BinMemberAuthenticationPayload for you.

    You can now write your authenticated and signed functions as follows:

    ::

        @lazy_wrapper(IntroductionRequestPayload, IntroductionResponsePayload)
        def on_message(peer: Peer,
                       payload1: IntroductionRequestPayload,
                       payload2: IntroductionResponsePayload):
            pass
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, source_address, data):
            # UNPACK
            auth, _ = self.serializer.unpack_serializable(BinMemberAuthenticationPayload, data, offset=23)
            signature_valid, remainder = self._verify_signature(auth, data)
            unpacked = self.serializer.unpack_serializable_list(payloads, remainder, offset=23)
            # ASSERT
            if not signature_valid:
                raise PacketDecodingError("Incoming packet %s has an invalid signature" %
                                          str([payload_class.__name__ for payload_class in payloads]))
            # PRODUCE
            peer = (self.network.verified_by_public_key_bin.get(auth.public_key_bin)
                    or Peer(auth.public_key_bin, source_address))
            return func(self, peer, *unpacked)
        return wrapper
    return decorator


def lazy_wrapper_wd(*payloads: AnyPayloadType):
    """
    This function wrapper will unpack the BinMemberAuthenticationPayload for you, as well as pass the raw data to the
    decorated function

    You can now write your authenticated and signed functions as follows:

    ::

        @lazy_wrapper_wd(IntroductionRequestPayload, IntroductionResponsePayload)
        def on_message(peer: Peer,
                       payload1: IntroductionRequestPayload,
                       payload2: IntroductionResponsePayload,
                       data: bytes):
            pass
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, source_address, data):
            # UNPACK
            auth, _ = self.serializer.unpack_serializable(BinMemberAuthenticationPayload, data, offset=23)
            signature_valid, remainder = self._verify_signature(auth, data)
            unpacked = self.serializer.unpack_serializable_list(payloads, remainder, offset=23)
            # ASSERT
            if not signature_valid:
                raise PacketDecodingError("Incoming packet %s has an invalid signature" %
                                          str([payload_class.__name__ for payload_class in payloads]))
            # PRODUCE
            output = unpacked + [data]
            peer = (self.network.verified_by_public_key_bin.get(auth.public_key_bin)
                    or Peer(auth.public_key_bin, source_address))
            return func(self, peer, *output)
        return wrapper
    return decorator


def lazy_wrapper_unsigned(*payloads: AnyPayloadType):
    """
    This function wrapper will unpack just the normal payloads for you.

    You can now write your non-authenticated and signed functions as follows:

    ::

        @lazy_wrapper_unsigned(IntroductionRequestPayload, IntroductionResponsePayload)
        def on_message(source_address: Address,
                       payload1: IntroductionRequestPayload,
                       payload2: IntroductionResponsePayload):
            pass
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, source_address, data):
            # UNPACK
            unpacked = self.serializer.unpack_serializable_list(payloads, data, offset=23)
            return func(self, source_address, *unpacked)
        return wrapper
    return decorator


def lazy_wrapper_unsigned_wd(*payloads: AnyPayloadType):
    """
    This function wrapper will unpack just the normal payloads for you, as well as pass the raw data to the decorated
    function

    You can now write your non-authenticated and signed functions as follows:

    ::

        @lazy_wrapper_unsigned_wd(IntroductionRequestPayload, IntroductionResponsePayload)
        def on_message(source_address: Address,
                       payload1: IntroductionRequestPayload,
                       payload2: IntroductionResponsePayload,
                       data: bytes):
            pass
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, source_address, data):

            @lazy_wrapper_unsigned(*payloads)
            def inner_wrapper(inner_self, inner_source_address, *pyls):
                combo = list(pyls) + [data]
                return func(inner_self, inner_source_address, *combo)

            return inner_wrapper(self, source_address, data)
        return wrapper
    return decorator


class EZPackOverlay(Overlay, ABC):

    @abstractmethod
    def get_prefix(self) -> bytes:
        pass

    def ez_send(self, peer: Peer, *payloads: AnyPayload, **kwargs) -> None:
        """
        Send a Payload instance (with a defined `msg_id` field) to a peer.
        If you supply more than one Payload instance, the `msg_id` of the LAST instance will be used.

        :param peer: the peer to send to
        :param sig: whether or not to sign this message
        :type sig: bool
        :param payloads: the list of Payload instances to serialize
        """
        self._ez_senda(peer.address, *payloads, **kwargs)

    def _ez_senda(self, address: Address, *payloads: AnyPayload, **kwargs) -> None:
        """
        Send a Payload instance to an address.

        You will probably not need this, try to use `ez_send` instead.

        :param address: the address to send to
        :param sig: whether or not to sign this message
        :type sig: bool
        :param payloads: the list of Payload instances to serialize
        """

        # We promise the typing system that the ``msg_id`` is defined for the last payload.
        # Strictly speaking we should introduce a ``LastPayloadWithMessageID`` type, but this is annoying to work with.
        self.endpoint.send(address, self.ezr_pack(payloads[-1].msg_id, *payloads, **kwargs))  # type:ignore

    def ezr_pack(self, msg_num: int, *payloads: AnyPayload, **kwargs) -> bytes:
        """
        The easier way to pack your messages. Supply with the message number and the Payloads you want to serialize.
        Optionally you can choose to sign the message.

        :param msg_num: the message number to claim for this message
        :param sig: whether or not to sign this message
        :type sig: bool
        :param payloads: the list of Payload instances to serialize
        :return: the serialized message
        """
        sig = kwargs.get('sig', True)
        if sig:
            payloads = (BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()),) + payloads
        return self._ez_pack(self.get_prefix(), msg_num, payloads, sig)

    def _ez_pack(self, prefix: bytes, msg_num: int, payloads: Iterable[AnyPayload], sig: bool = True) -> bytes:
        packet = prefix + bytes([msg_num]) + self.serializer.pack_serializable_list(payloads)
        if sig:
            packet += default_eccrypto.create_signature(self.my_peer.key, packet)
        return packet

    def _verify_signature(self, auth: BinMemberAuthenticationPayload, data: bytes) -> Tuple[bool, bytes]:
        ec = default_eccrypto
        public_key = ec.key_from_public_bin(auth.public_key_bin)
        signature_length = ec.get_signature_length(public_key)
        remainder = data[2 + len(auth.public_key_bin):-signature_length]
        signature = data[-signature_length:]
        return ec.is_valid_signature(public_key, data[:-signature_length], signature), remainder

    def _ez_unpack_auth(self,
                        payload_class: AnyPayloadType,
                        data: bytes) -> Tuple[BinMemberAuthenticationPayload, GlobalTimeDistributionPayload,
                                              AnyPayload]:
        # UNPACK
        auth, _ = self.serializer.unpack_serializable(BinMemberAuthenticationPayload, data, offset=23)
        signature_valid, remainder = self._verify_signature(auth, data)
        format = [GlobalTimeDistributionPayload, payload_class]
        unpacked = self.serializer.unpack_serializable_list(format, remainder, offset=23)
        # ASSERT
        if not signature_valid:
            raise PacketDecodingError("Incoming packet %s has an invalid signature" % payload_class.__name__)
        # PRODUCE
        return auth, unpacked[0], unpacked[1]

    def _ez_unpack_noauth(self,
                          payload_class: AnyPayloadType,
                          data: bytes,
                          global_time: bool = True) -> Union[List[AnyPayload], AnyPayload]:
        # UNPACK
        format = [GlobalTimeDistributionPayload, payload_class] if global_time else [payload_class]
        unpacked = self.serializer.unpack_serializable_list(format, data, offset=23)
        # PRODUCE
        return unpacked if global_time else unpacked[0]


class PacketDecodingError(RuntimeError):
    pass
