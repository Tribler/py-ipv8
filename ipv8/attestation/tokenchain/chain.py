import logging
from collections import OrderedDict
from hashlib import sha3_256
from typing import Optional, Set, TypeVar

from .token import Token
from ...keyvault.keys import PrivateKey, PublicKey


TokenChainType = TypeVar('TokenChainType', bound='TokenChain')


class TokenChain(object):
    """
    Raw datatype for chains of double pointers (Tokens).

    It takes the following form:

        SHA3-256(PUBLIC KEY) <- TOKEN <- TOKEN <- ...

    Each token also has a SHA3-256 pointer to external content.

    Note that the public key has to be known to fulfil the genesis pointer to the SHA3-256 hash (the public key is not
    stored in the Tokens themselves).
    """

    def __init__(self, public_key: Optional[PublicKey] = None, private_key: Optional[PrivateKey] = None) -> None:
        """
        Create a new view of another's chain by specifying a public key or create your own chain by supplying
        a private key.

        :param public_key: the public key of the owner of this chain.
        :param private_key: the private key to use to add tokens to this chain.
        """
        super(TokenChain, self).__init__()
        self._logger = logging.getLogger(self.__class__.__name__)

        self.chain = []
        self.chain_lookup = {}
        self.unchained = OrderedDict()
        self.unchained_max_size = 100

        if public_key is not None and private_key is None:
            self.public_key = public_key
            self.private_key = None
        elif public_key is None and private_key is not None:
            self.private_key = private_key
            self.public_key = private_key.pub()
        else:
            raise RuntimeError("Specify either public_key or private_key!")

        self.genesis_hash = sha3_256(self.public_key.key_to_bin()).digest()

    def add(self, content: bytes) -> Token:
        """
        Tokenize new content and add it to this chain.

        :param content: the content to tokenize and add to this chain.
        :returns: the newly added Token.
        """
        if self.private_key is None:
            raise RuntimeError("Attempted to create token without a key!")
        previous_hash = self.genesis_hash if not self.chain else self.chain[-1].get_hash()
        return self._append(Token(previous_hash, content=content, private_key=self.private_key))

    def gather_token(self, token: Token) -> Optional[Token]:
        """
        Attempt to add received data to this chain.
        Data may be pending missing Tokens before being added to the chain structure.

        :param token: the token to attempt to add.
        :returns: the newly added token or None if the operation was not successful.
        """
        if token.verify(self.public_key):
            if token.previous_token_hash == (self.chain[-1].get_hash() if self.chain else self.genesis_hash):
                self._append_chain_reaction_token(token)
            elif token.get_hash() not in self.chain_lookup:
                self.unchained[token] = None
                if len(self.unchained) > self.unchained_max_size:
                    self.unchained.popitem(False)
                self._logger.info(f"Delaying unchained token {token}!")
            else:
                shadow_token = self.chain[self.chain_lookup[token.get_hash()]]
                if shadow_token.content is None and token.content is not None:
                    shadow_token.receive_content(token.content)
                return shadow_token
            return token
        return None

    def content_matches(self, index: int, content: bytes) -> bool:
        """
        Check if the Token at a certain index stores certain content.

        :param index: the index of the chain to check.
        :param content: the content to match.
        :returns: whether the content matches or not.
        """
        return self.chain[index].receive_content(content)

    def get_missing(self) -> Set[bytes]:
        """
        Gather all the preceding hashes that have been specified but not collected.

        :returns: the set of missing hashes.
        """
        return {token.previous_token_hash for token in self.unchained}

    def verify(self, start_index: int = 0, stop_index: Optional[int] = None) -> bool:
        """
        Verify the chain integrity: all tokens are correctly signed and stored at the right index.

        Should only be done when loading from database or direct writing (don't do that) by programmers.

        :param start_index: the index to start checking from.
        :param stop_index: the index to stop checking at.
        :returns: whether all tokens were correct, signed and at the right chain index.
        """
        previous = self.genesis_hash if start_index == 0 else self.chain[start_index - 1].get_hash()
        current = 0
        for token in self.chain[start_index:stop_index]:
            if token.previous_token_hash != previous:
                return False
            if not token.verify(self.public_key):
                return False
            previous = token.get_hash()
            current += 1
        return True

    def serialize_public(self, start: int = 0, up_to: Optional[int] = None) -> bytes:
        """
        Serialize all the signed double pointers of this chain.

        :param start: the index to start at.
        :param up_to: the index to stop at.
        """
        return b''.join(token.get_plaintext_signed() for token in self.chain[start:up_to])

    @classmethod
    def unserialize_public(self, s: bytes, public_key: PublicKey) -> TokenChainType:
        """
        Given a serialized chain format, unserialize with the given public key.

        :param s: the serialized chain data.
        :param public_key: the public key to unserialize for.
        """
        sig_len = public_key.get_signature_length()
        chunk_size = 64 + sig_len
        chain = TokenChain(public_key=public_key)
        for i in range(0, len(s), chunk_size):
            chain.gather_token(Token.unserialize(s, public_key, offset=i))
        return chain

    def _append(self, token: Token) -> Token:
        """
        Append a token to this chain. Never call this directly: use add() instead!

        :param token: the token to append to the chain.
        :returns: the appended token.
        """
        self.chain_lookup[token.get_hash()] = len(self.chain)
        self.chain.append(token)
        return token

    def _append_chain_reaction_token(self, token: Token) -> None:
        """
        Append the given token and wake up any tokens stored in `unchained` that pointed to it.

        :param token: the token to append to the chain.
        """
        self._append(token)
        retry_token = None
        for lost_token in self.unchained:
            if lost_token.previous_token_hash == self.chain[-1].get_hash():
                retry_token = lost_token
                break
        if retry_token is not None:
            self.unchained.pop(retry_token)
            if self.gather_token(retry_token) is None:
                self._logger.warning(f"Dropped illegal token {retry_token}!")
