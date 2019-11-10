def _should_use_new_crypto_version():
    """
    Checks if this python-cryptography supports the new signing and verifying methods.

    As of version 1.5.x cryptography has the `sign` and `verify` methods.
    As of version 2.x, the `signer` and `verifier` methods have been deprecated.

    :return: whether we should use the new signing/verifying methods
    :rtype: bool
    """
    import cryptography
    from distutils.version import LooseVersion
    try:
        cryptography_version = LooseVersion(cryptography.__version__)
        return cryptography_version >= LooseVersion('1.5')
    except (AttributeError, UnicodeEncodeError):
        # Empty strings raise AttributeError
        # Illegal unicode characters raise UnicodeEncodeError
        return False


NEW_CRYPTOGRAPHY_SIGN_VERSION = _should_use_new_crypto_version()


__all__ = ['NEW_CRYPTOGRAPHY_SIGN_VERSION']
