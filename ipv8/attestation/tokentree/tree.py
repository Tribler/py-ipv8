from __future__ import annotations

import logging
from collections import OrderedDict
from hashlib import sha3_256
from typing import TYPE_CHECKING, Set

from .token import Token

if TYPE_CHECKING:
    from ...types import PrivateKey, PublicKey


class TokenTree:
    """
    Raw datatype for chains of double pointers (Tokens).

    It takes the following form:

        SHA3-256(PUBLIC KEY) <- TOKEN <- TOKEN <- ...

    Each token also has a SHA3-256 pointer to external content.

    Note that the public key has to be known to fulfil the genesis pointer to the SHA3-256 hash (the public key is not
    stored in the Tokens themselves).
    """

    def __init__(self, public_key: PublicKey | None = None, private_key: PrivateKey | None = None) -> None:
        """
        Create a new view of another's chain by specifying a public key or create your own chain by supplying
        a private key.

        :param public_key: the public key of the owner of this chain.
        :param private_key: the private key to use to add tokens to this chain.
        """
        super().__init__()
        self._logger = logging.getLogger(self.__class__.__name__)

        self.elements: dict[bytes, Token] = {}
        self.unchained: OrderedDict = OrderedDict()
        self.unchained_max_size = 100

        if public_key is not None and private_key is None:
            self.public_key = public_key.pub()
            self.private_key = None
        elif public_key is None and private_key is not None:
            self.private_key = private_key
            self.public_key = private_key.pub()
        else:
            msg = "Specify either public_key or private_key!"
            raise RuntimeError(msg)

        self.genesis_hash = sha3_256(self.public_key.key_to_bin()).digest()

    def add(self, content: bytes, after: Token | None = None) -> Token:
        """
        Tokenize new content and add it to this chain.

        :param content: the content to tokenize and add to this chain.
        :param after: the token to succeed.
        :returns: the newly added Token.
        """
        if self.private_key is None:
            msg = "Attempted to create token without a key!"
            raise RuntimeError(msg)
        previous_hash = self.genesis_hash if not after else after.get_hash()
        return self._append(Token(previous_hash, content=content, private_key=self.private_key))

    def add_by_hash(self, content_hash: bytes, after: Token | None = None) -> Token:
        """
        Add the promise of tokenized content to this chain.

        :param content_hash: the hash of the content to add to this chain.
        :param after: the token to succeed.
        :returns: the newly added Token.
        """
        if self.private_key is None:
            msg = "Attempted to create token without a key!"
            raise RuntimeError(msg)
        previous_hash = self.genesis_hash if not after else after.get_hash()
        return self._append(Token(previous_hash, content_hash=content_hash, private_key=self.private_key))

    def gather_token(self, token: Token) -> Token | None:
        """
        Attempt to add received data to this chain.
        Data may be pending missing Tokens before being added to the chain structure.

        :param token: the token to attempt to add.
        :returns: the newly added token or None if the operation was not successful.
        """
        if token.verify(self.public_key):
            if token.previous_token_hash != self.genesis_hash and token.previous_token_hash not in self.elements:
                self.unchained[token] = None
                if len(self.unchained) > self.unchained_max_size:
                    self.unchained.popitem(False)
                self._logger.info("Delaying unchained token %s!", token)
                return None
            if token.get_hash() in self.elements:
                shadow_token = self.elements[token.get_hash()]
                if shadow_token.content is None and token.content is not None:
                    shadow_token.receive_content(token.content)
                return shadow_token
            self._append_chain_reaction_token(token)
            return token
        return None

    def get_missing(self) -> Set[bytes]:
        """
        Gather all the preceding hashes that have been specified but not collected.

        :returns: the set of missing hashes.
        """
        return {token.previous_token_hash for token in self.unchained}

    def verify(self, token: Token, maxdepth: int = 1000) -> bool:
        """
        Verify the chain integrity: all preceding tokens are correctly signed and stored.

        Should only be done when loading from database or direct writing (don't do that) by programmers.

        :param token: the token to start checking from.
        :param maxdepth: the maximum amount of steps to verify (after which this returns False).
        :returns: whether all preceding tokens were correct and signed.
        """
        current = token
        steps = 0
        while maxdepth == -1 or maxdepth > steps:
            if not current.verify(self.public_key):
                return False
            if current.previous_token_hash == self.genesis_hash:
                break
            if current.previous_token_hash not in self.elements:
                return False
            current = self.elements[current.previous_token_hash]
            steps += 1
        return steps < maxdepth

    def get_root_path(self, token: Token, maxdepth: int = 1000) -> list[Token]:
        """
        Calculate the path back to the root, including this token.

        :param token: the token to start checking from.
        :param maxdepth: the maximum amount of steps (after which this returns an empty list).
        :returns: the length of the path back to the root or an empty list if it doesn't exist.
        """
        current = token
        steps = 0
        path = [token]
        while maxdepth == -1 or maxdepth > steps:
            if not current.verify(self.public_key):
                return []
            if current.previous_token_hash == self.genesis_hash:
                break
            if current.previous_token_hash not in self.elements:
                return []
            current = self.elements[current.previous_token_hash]
            path += [current]
            steps += 1
        if steps < maxdepth:
            return path
        return []

    def serialize_public(self, up_to: Token | None = None) -> bytes:
        """
        Serialize all the signed double pointers of this chain.

        :param up_to: the token to work back from to the root of the tree.
        """
        if up_to:
            # End specified, move back to the root
            out = up_to.get_plaintext_signed()
            next_token = up_to.previous_token_hash
            while next_token in self.elements:
                token = self.elements[next_token]
                out += token.get_plaintext_signed()
                next_token = token.previous_token_hash
            return out
        # Do the full tree dump.
        return b''.join(token.get_plaintext_signed() for token in self.elements.values())

    def unserialize_public(self, s: bytes) -> bool:
        """
        Given a serialized tree format, unserialize with the tree's public key.

        :param s: the serialized tree data.
        :returns: if all information was correctly unserialized.
        """
        sig_len = self.public_key.get_signature_length()
        chunk_size = 64 + sig_len
        correct = True
        for i in range(0, len(s), chunk_size):
            correct &= self.gather_token(Token.unserialize(s, self.public_key, offset=i)) is not None
        return correct

    def _append(self, token: Token) -> Token:
        """
        Append a token to this tree. Never call this directly: use add() instead!

        :param token: the token to append to the chain.
        :returns: the appended token.
        """
        self.elements[token.get_hash()] = token
        return token

    def _append_chain_reaction_token(self, token: Token) -> None:
        """
        Append the given token and wake up any tokens stored in `unchained` that pointed to it.

        :param token: the token to append to the chain.
        """
        self._append(token)
        retry_token = None
        for lost_token in self.unchained:
            if lost_token.previous_token_hash == token.get_hash():
                retry_token = lost_token
                break
        if retry_token is not None:
            self.unchained.pop(retry_token)
            if self.gather_token(retry_token) is None:
                self._logger.warning("Dropped illegal token %s!", retry_token)
