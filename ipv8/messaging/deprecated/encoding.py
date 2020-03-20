import logging
from json import dumps
from urllib.parse import ParseResult, parse_qsl, unquote, urlencode, urlparse

from ...util import cast_to_bin

logger = logging.getLogger(__name__)


def _a_encode_int(value, mapping):
    """
    42 --> ('2', 'i', '42')
    """
    assert isinstance(value, int), "VALUE has invalid type: %s" % type(value)
    value = str(value).encode("UTF-8")
    return str(len(value)).encode("UTF-8"), b"i", value


def _a_encode_long(value, mapping):
    """
    42 --> ('2', 'J', '42')
    """
    assert isinstance(value, int) and not isinstance(value, int), "VALUE has invalid type: %s" % type(value)
    value = str(value).encode("UTF-8")
    return str(len(value)).encode("UTF-8"), b"J", value


def _a_encode_float(value, mapping):
    """
    4.2 --> ('3', 'f', '4.2')
    """
    assert isinstance(value, float), "VALUE has invalid type: %s" % type(value)
    value = str(value).encode("UTF-8")
    return str(len(value)).encode("UTF-8"), b"f", value


def _a_encode_unicode(value, mapping):
    """
    'foo-bar' --> ('7', 's', 'foo-bar')
    """
    assert isinstance(value, str), "VALUE has invalid type: %s" % type(value)
    value = value.encode("UTF-8")
    return str(len(value)).encode("UTF-8"), b"s", value


def _a_encode_bytes(value, mapping):
    """
    'foo-bar' --> ('7', 'b', 'foo-bar')
    """
    assert isinstance(value, (bytes, str)), "VALUE has invalid type: %s" % type(value)
    return str(len(value)).encode("UTF-8"), b"b", cast_to_bin(value)


def _a_encode_str(value, mapping):
    """
    This can either be a Python3 str (unicode) or Python2 str (bytes).
    The difference is that a Python3 str is unicode and a Python2 str is not.
    """
    if isinstance(value, str):
        return _a_encode_unicode(value, mapping)
    else:
        return _a_encode_bytes(value, mapping)


def _a_encode_list(values, mapping):
    """
    [1,2,3] --> ['3', 'l', '1', 'i', '1', '1', 'i', '2', '1', 'i', '3']
    """
    assert isinstance(values, list), "VALUE has invalid type: %s" % type(values)
    encoded = [str(len(values)).encode("UTF-8"), b"l"]
    extend = encoded.extend
    for value in values:
        extend(mapping[type(value).__name__](value, mapping))
    return encoded


def _a_encode_set(values, mapping):
    """
    [1,2,3] --> ['3', 'l', '1', 'i', '1', '1', 'i', '2', '1', 'i', '3']
    """
    assert isinstance(values, set), "VALUE has invalid type: %s" % type(values)
    encoded = [str(len(values)).encode("UTF-8"), b"L"]
    extend = encoded.extend
    for value in values:
        extend(mapping[type(value).__name__](value, mapping))
    return encoded


def _a_encode_tuple(values, mapping):
    """
    (1,2) --> ['2', 't', '1', 'i', '1', '1', 'i', '2']
    """
    assert isinstance(values, tuple), "VALUE has invalid type: %s" % type(values)
    encoded = [str(len(values)).encode("UTF-8"), b"t"]
    extend = encoded.extend
    for value in values:
        extend(mapping[type(value).__name__](value, mapping))
    return encoded


def _a_encode_dictionary(values, mapping):
    """
    {'foo':'bar', 'moo':'milk'} --> ['2', 'd', '3', 's', 'foo', '3', 's', 'bar', '3', 's', 'moo', '4', 's', 'milk']
    """
    assert isinstance(values, dict), "VALUE has invalid type: %s" % type(values)
    encoded = [str(len(values)).encode("UTF-8"), b"d"]
    extend = encoded.extend
    for key, value in values.items():
        assert type(key).__name__ in mapping, (key, values)
        assert type(value).__name__ in mapping, (value, values)
        extend(mapping[type(key).__name__](key, mapping))
        extend(mapping[type(value).__name__](value, mapping))
    return encoded


def _a_encode_none(value, mapping):
    """
    None --> ['0', 'n']
    """
    return [b'0n']


def _a_encode_bool(value, mapping):
    """
    True  --> ['0', 'T']
    False --> ['0', 'F']
    """
    return [b'0T' if value else b'0F']


_a_encode_mapping = {'int': _a_encode_int,
                     'long': _a_encode_long,
                     'float': _a_encode_float,
                     'unicode': _a_encode_unicode,
                     'str': _a_encode_str,
                     'bytes': _a_encode_bytes,
                     'list': _a_encode_list,
                     'set': _a_encode_set,
                     'OrderedSet': _a_encode_set,
                     'tuple': _a_encode_tuple,
                     'dict': _a_encode_dictionary,
                     'OrderedDict': _a_encode_dictionary,
                     'NoneType': _a_encode_none,
                     'bool': _a_encode_bool}


def bytes_to_uint(stream, offset=0):
    assert isinstance(stream, str)
    assert isinstance(offset, int)
    assert offset >= 0
    bit8 = 16 * 8
    mask7 = 2 ** 7 - 1
    i = 0
    while offset < len(stream):
        c = ord(stream[offset])
        i |= mask7 & c
        if not bit8 & c:
            return i
        offset += 1
        i <<= 7
    raise ValueError()


def encode(data, version="a"):
    """
    Encode DATA into version 'a' binary stream.

    DATA can be any: int, float, string, unicode, list, tuple, or
    dictionary.

    Lists are considered to be tuples.  I.e. when decoding an
    encoded list it will come out as a tuple.

    The encoding process is done using version 'a' which is
    indicated by the first byte of the resulting binary stream.
    """
    assert isinstance(version, str)
    if version == "a":
        return b"a" + b"".join(_a_encode_mapping[type(data).__name__](data, _a_encode_mapping))

    raise ValueError("Unknown encode version")


def _a_decode_int(stream, offset, count, _):
    """
    'a2i42',3,2 --> 5,42
    """
    return offset + count, int(stream[offset:offset + count])


def _a_decode_long(stream, offset, count, _):
    """
    'a2J42',3,2 --> 5,42
    """
    return offset + count, int(stream[offset:offset + count])


def _a_decode_float(stream, offset, count, _):
    """
    'a3f4.2',3,3 --> 6,4.2
    """
    return offset + count, float(stream[offset:offset + count])


def _a_decode_unicode(stream, offset, count, _):
    """
    'a3sbar',3,3 --> 6,u'bar'
    """
    if len(stream) >= offset + count:
        return offset + count, stream[offset:offset + count].decode("UTF-8")
    else:
        raise ValueError("Invalid stream length", len(stream), offset + count)


def _a_decode_unicode_safe(stream, offset, count, _):
    """
    'a3sba\x80',3,3 --> 6,u'ba\x80'
    """
    if len(stream) >= offset + count:
        return offset + count, "".join([chr(c) for c in stream[offset:offset + count]])
    else:
        raise ValueError("Invalid stream length", len(stream), offset + count)


def _a_decode_bytes(stream, offset, count, _):
    """
    'a3bfoo',3,3 --> 6,'foo'
    """
    if len(stream) >= offset + count:
        return offset + count, stream[offset:offset + count]
    else:
        raise ValueError("Invalid stream length", len(stream), offset + count)


def _a_decode_list(stream, offset, count, mapping):
    """
    'a1l3i123',3,1 --> 8,[123]
    'a2l1i41i2',3,1 --> 8,[4,2]
    """
    container = []
    for _ in range(count):

        index = offset
        while 48 <= ord(stream[index:index + 1]) <= 57:
            index += 1
        offset, value = mapping[stream[index:index + 1]](stream, index + 1, int(stream[offset:index]), mapping)
        container.append(value)

    return offset, container


def _a_decode_set(stream, offset, count, mapping):
    """
    'a1L3i123',3,1 --> 8,set(123)
    'a2L1i41i2',3,1 --> 8,set(4,2)
    """
    container = set()
    for _ in range(count):

        index = offset
        while 48 <= ord(stream[index:index + 1]) <= 57:
            index += 1
        offset, value = mapping[stream[index:index + 1]](stream, index + 1, int(stream[offset:index]), mapping)
        container.add(value)

    return offset, container


def _a_decode_tuple(stream, offset, count, mapping):
    """
    'a1t3i123',3,1 --> 8,[123]
    'a2t1i41i2',3,1 --> 8,[4,2]
    """
    container = []
    for _ in range(count):

        index = offset
        while 48 <= ord(stream[index:index + 1]) <= 57:
            index += 1
        offset, value = mapping[stream[index:index + 1]](stream, index + 1, int(stream[offset:index]), mapping)
        container.append(value)

    return offset, tuple(container)


def _a_decode_dictionary(stream, offset, count, mapping):
    """
    'a2d3sfoo3sbar3smoo4smilk',3,2 -> 24,{'foo':'bar', 'moo':'milk'}
    """
    container = {}
    for _ in range(count):

        index = offset
        while 48 <= ord(stream[index:index + 1]) <= 57:
            index += 1
        offset, key = mapping[stream[index:index + 1]](stream, index + 1, int(stream[offset:index]), mapping)

        index = offset
        while 48 <= ord(stream[index:index + 1]) <= 57:
            index += 1
        offset, value = mapping[stream[index:index + 1]](stream, index + 1, int(stream[offset:index]), mapping)

        container[key] = value

    if len(container) < count:
        raise ValueError("Duplicate key in dictionary")
    return offset, container


def _a_decode_none(stream, offset, count, mapping):
    """
    'a0n',3,0 -> 3,None
    """
    assert count == 0
    return offset, None


def _a_decode_true(stream, offset, count, mapping):
    """
    'a0T',3,1 -> 3,True
    """
    assert count == 0
    return offset, True


def _a_decode_false(stream, offset, count, mapping):
    """
    'a0F',3,1 -> 3,False
    """
    assert count == 0
    return offset, False


_a_decode_mapping = {b"i": _a_decode_int,
                     b"J": _a_decode_long,
                     b"f": _a_decode_float,
                     b"s": _a_decode_unicode,
                     b"b": _a_decode_bytes,
                     b"l": _a_decode_list,
                     b"L": _a_decode_set,
                     b"t": _a_decode_tuple,
                     b"d": _a_decode_dictionary,
                     b"n": _a_decode_none,
                     b"T": _a_decode_true,
                     b"F": _a_decode_false}

_a_decode_mapping_utf8 = _a_decode_mapping.copy()
_a_decode_mapping_utf8[b"b"] = _a_decode_unicode_safe


def decode(stream, offset=0, cast_utf8=False):
    """
    Decode STREAM from index OFFSET and further into a python data
    structure.

    Returns the new OFFSET of the stream and the decoded data.

    Only version 'a' decoding is supported.  This version is
    indicated by the first byte in the binary STREAM.

    :param cast_utf8: Convert all bytes strings to unicode.
    """
    assert isinstance(stream, bytes), "STREAM has invalid type: %s" % type(stream)
    assert isinstance(offset, int), "OFFSET has invalid type: %s" % type(offset)

    decode_mapping = _a_decode_mapping_utf8 if cast_utf8 else _a_decode_mapping

    if stream[offset:offset + 1] == b"a":
        index = offset + 1
        while 48 <= ord(stream[index:index + 1]) <= 57:
            index += 1
        return decode_mapping[stream[index:index + 1]](stream, index + 1, int(stream[offset + 1:index]),
                                                       decode_mapping)

    raise ValueError("Unknown version found")


def add_url_params(url, params):
    """ Add GET params to provided URL being aware of existing.

    :param url: string of target URL
    :param params: dict containing requested params to be added
    :return: string with updated URL

    >> url = 'http://stackoverflow.com/test?answers=true'
    >> new_params = {'answers': False, 'data': ['some','values']}
    >> add_url_params(url, new_params)
    'http://stackoverflow.com/test?data=some&data=values&answers=false'
    """
    # Unquoting URL first so we don't loose existing args
    url = unquote(url)
    # Extracting url info
    parsed_url = urlparse(url)
    # Extracting URL arguments from parsed URL
    get_args = parsed_url.query
    # Converting URL arguments to dict
    parsed_get_args = dict(parse_qsl(get_args))
    # Merging URL arguments dict with new params
    parsed_get_args.update(params)

    # Bool and Dict values should be converted to json-friendly values
    # you may throw this part away if you don't like it :)
    parsed_get_args.update(
        {k: dumps(v) for k, v in parsed_get_args.items()
         if isinstance(v, (bool, dict))}
    )

    # Converting URL argument to proper query string
    encoded_get_args = urlencode(parsed_get_args, doseq=True)
    # Creating new parsed result object based on provided with new
    # URL arguments. Same thing happens inside of urlparse.
    new_url = ParseResult(
        parsed_url.scheme, parsed_url.netloc, parsed_url.path,
        parsed_url.params, encoded_get_args, parsed_url.fragment
    ).geturl()

    return new_url
