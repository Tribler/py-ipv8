from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.backend import Backend

# ruff: noqa: SLF001


def generate_safe_prime(bit_length: int, backend: Backend = default_backend()) -> int:  # noqa: B008
    """
    Generate a 'safe' prime p ((p-1)/2 is also prime).

    :param bit_length: the length of the generated prime in bits
    :type bit_length: int
    :param backend: the cryptography backend to use
    :type backend: Backend
    :return: the generated prime
    :rtype: int
    """
    generated = backend._lib.BN_new()
    err = backend._lib.BN_generate_prime_ex(generated, bit_length, 1,
                                            backend._ffi.NULL, backend._ffi.NULL, backend._ffi.NULL)
    # If the return value is 0, the generation failed
    if err == 0:
        backend._lib.BN_clear_free(generated)
        msg = "Failed to generate prime!"
        raise RuntimeError(msg)
    # We cannot simply convert the output to int (too long), use the hex representation and port that to int
    generated_hex = backend._lib.BN_bn2hex(generated)
    out = int(backend._ffi.string(generated_hex), 16)
    # Cleanup the memory
    backend._lib.OPENSSL_free(generated_hex)
    backend._lib.BN_set_word(generated, 0)
    backend._lib.BN_free(generated)
    return out


def is_prime(number: int, backend: Backend = default_backend()) -> bool:  # noqa: B008
    """
    Check a number for primality.

    :param number: the number to check for primality
    :type number: int
    :param backend: the cryptography backend to use
    :type backend: Backend
    :return: True is the n is expected to be prime, False otherwise
    :rtype: bool
    """
    # We cannot simply convert the output to int (too long), use the hex representation
    hex_n = hex(number)[2:]
    if hex_n.endswith('L'):
        hex_n = hex_n[:-1]
    # hex() outputs a unicode string in Python 3
    bhex_n = hex_n.encode()
    generated = backend._lib.BN_new()
    bn_pp = backend._ffi.new("BIGNUM **", generated)
    err = backend._lib.BN_hex2bn(bn_pp, bhex_n)
    # If the return value is 0, the conversion to hex failed
    if err == 0:
        backend._lib.BN_clear_free(generated)
        msg = "Failed to read BIGNUM from hex string!"
        raise RuntimeError(msg)
    result = backend._lib.BN_is_prime_ex(generated, backend._lib.BN_prime_checks_for_size(int(len(bhex_n) * 8)),
                                         backend._ffi.NULL, backend._ffi.NULL)
    backend._lib.BN_set_word(generated, 0)
    backend._lib.BN_free(generated)
    return result == 1
