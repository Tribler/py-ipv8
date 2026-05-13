from __future__ import annotations

import abc
import logging
from typing import TYPE_CHECKING

from ipv8_rust_tunnels import SessionKeys, crypto_auth, crypto_auth_verify
from ipv8_rust_tunnels import generate_session_keys as _generate_session_keys

from ...keyvault.crypto import ECCrypto
from ...keyvault.keys import PrivateKey, PublicKey
from ...keyvault.private.openssl import OpenSSLSK
from ..interfaces.endpoint import Endpoint, EndpointListener
from .payload import NO_CRYPTO_PACKETS, CellPayload
from .tunnel import (
    BACKWARD,
    CIRCUIT_TYPE_RP_DOWNLOADER,
    CIRCUIT_TYPE_RP_SEEDER,
    FORWARD,
    Circuit,
    Hop,
    RelayRoute,
)

if TYPE_CHECKING:
    from ..interfaces.udp.endpoint import Address
    from .community import TunnelCommunity, TunnelSettings
    from .exit_socket import TunnelExitSocket


class CryptoException(Exception):
    """
    Exception for when anything goes wrong with sessions, encoding, and decoding.
    """


class CryptoEndpoint(metaclass=abc.ABCMeta):
    """
    UDP endpoint capable of sending/relaying/exiting CellPayloads.
    """

    def __init__(self) -> None:
        """
        Create new crypto endpoint.
        """
        self.settings: TunnelSettings | None = None
        self.prefix = b"\x00" * 22
        self.circuits: dict[int, Circuit] = {}
        self.relays: dict[int, RelayRoute] = {}
        self.exit_sockets: dict[int, TunnelExitSocket] = {}
        self.logger = logging.getLogger(self.__class__.__name__)

    @abc.abstractmethod
    def setup_tunnels(self, tunnel_community: TunnelCommunity, settings: TunnelSettings) -> None:
        """
        Set up the TunnelCommunity.
        """

    @abc.abstractmethod
    def send_cell(self, target_addr: Address, cell: CellPayload) -> None:
        """
        Send the given payload directly to the given peer with the appropriate encryption rules.
        """


class PythonCryptoEndpoint(CryptoEndpoint, EndpointListener):
    """
    UDP endpoint capable of sending/relaying/exiting CellPayloads.
    """

    def __init__(self, endpoint: Endpoint) -> None:
        """
        Create new crypto endpoint using a preexisting endpoint for network communication.
        """
        EndpointListener.__init__(self, endpoint)
        CryptoEndpoint.__init__(self)
        self.tunnel_community: TunnelCommunity | None = None

    def setup_tunnels(self, tunnel_community: TunnelCommunity, settings: TunnelSettings) -> None:
        """
        Set up the TunnelCommunity.
        """
        self.prefix = tunnel_community.get_prefix()
        self.settings = settings

        # Packets will go through the CryptoEndpoint before they end up in the tunnel community.
        self.endpoint.remove_listener(tunnel_community)
        # Ensure multiple calls don't keep adding the same listener.
        self.endpoint.remove_listener(self)
        self.endpoint.add_prefix_listener(self, self.prefix)
        self.tunnel_community = tunnel_community

    @property
    def max_relay_early(self) -> int:
        """
        Return the maximum number of relay_early cells that are allowed to pass a relay.
        """
        return self.settings.max_relay_early if self.settings else 8

    def on_packet(self, packet: tuple[Address, bytes], warn_unknown: bool = True) -> None:
        """
        Callback for when data is received on this endpoint.
        """
        source_address, datagram = packet
        if datagram.startswith(self.prefix) and datagram[22] == CellPayload.msg_id:
            self.process_cell(source_address, datagram)
        elif self.tunnel_community:
            self.tunnel_community.on_packet(packet)

    def send_cell(self, target_addr: Address, cell: CellPayload) -> None:
        """
        Send the given payload directly to the given peer with the appropriate encryption rules.
        """
        circuit_id = cell.circuit_id
        circuit = self.circuits.get(circuit_id)
        relay = self.relays.get(circuit_id)

        if circuit:
            cell.relay_early = cell.message[0] == 4 or circuit.relay_early_count < self.max_relay_early
            if cell.relay_early:
                circuit.relay_early_count += 1

        if not self.outgoing_crypto(cell):
            return

        packet = cell.to_bin(self.prefix)
        self.endpoint.send(target_addr, packet)

        tunnel_obj = circuit or relay
        if tunnel_obj:
            tunnel_obj.bytes_up += len(packet)

    def process_cell(self, source_address: Address, data: bytes) -> None:
        """
        Process incoming raw data, assumed to be a cell, originating from a given address.
        """
        cell = CellPayload.from_bin(data)
        circuit_id = cell.circuit_id

        next_relay = self.relays.get(circuit_id)
        if next_relay:
            this_relay = self.relays.get(next_relay.circuit_id)
            if this_relay:
                this_relay.beat_heart()
                this_relay.bytes_down += len(data)
            self.logger.debug("Relaying cell from circuit %d to %d", circuit_id, next_relay.circuit_id)
            self.relay_cell(cell)
            return

        if not self.incoming_crypto(cell):
            return

        self.logger.debug("Got cell(%s) from circuit %d (sender %s)", cell.message[0], circuit_id, source_address)

        if (not cell.relay_early and cell.message[0] == 4) or self.max_relay_early <= 0:
            self.logger.info("Dropping cell (missing or unexpected relay_early flag)")
            return
        if cell.plaintext and cell.message[0] not in NO_CRYPTO_PACKETS:
            self.logger.warning("Dropping cell (only create/created can have plaintext flag set)")
            return

        if not self.tunnel_community:
            self.logger.error("Could not handle cell: no listener set")
            return

        self.tunnel_community.on_packet((source_address, cell.to_bin(self.prefix)))

        circuit = self.circuits.get(cell.circuit_id)
        if circuit:
            circuit.beat_heart()
            circuit.bytes_down += len(data)

    def relay_cell(self, cell: CellPayload) -> None:
        """
        Forward the given cell, which contains the information needed for its own relaying.
        """
        if cell.plaintext:
            self.logger.warning("Dropping cell (cell not encrypted)")
            return

        next_relay = self.relays[cell.circuit_id]

        if cell.relay_early and next_relay.relay_early_count >= self.max_relay_early:
            self.logger.warning("Dropping cell (too many relay_early cells)")
            return

        try:
            if next_relay.rendezvous_relay:
                self.decrypt_cell(cell, FORWARD, next_relay.hop)
                this_relay = self.relays[next_relay.circuit_id]
                self.encrypt_cell(cell, BACKWARD, this_relay.hop)
                cell.relay_early = False
            else:
                direction = next_relay.direction
                if direction == FORWARD:
                    self.decrypt_cell(cell, direction, next_relay.hop)
                elif direction == BACKWARD:
                    self.encrypt_cell(cell, direction, next_relay.hop)

        except CryptoException as e:
            self.logger.warning(str(e))
            return

        cell.circuit_id = next_relay.circuit_id
        packet = cell.to_bin(self.prefix)
        self.endpoint.send(next_relay.hop.address, packet)
        next_relay.bytes_up += len(packet)
        next_relay.relay_early_count += 1

    def outgoing_crypto(self, cell: CellPayload) -> CellPayload | None:
        """
        Encrypt a CellPayload using the SessionKeys currently available in the routing table.
        """
        circuit_id = cell.circuit_id
        circuit = self.circuits.get(circuit_id)
        exit_socket = self.exit_sockets.get(circuit_id)
        relay = self.relays.get(circuit_id)

        try:
            if circuit:
                if circuit.hs_session_keys:
                    direction = FORWARD if circuit.ctype == CIRCUIT_TYPE_RP_SEEDER else BACKWARD
                    self.encrypt_cell(cell, direction, Hop(circuit.hop.peer, circuit.hs_session_keys))
                self.encrypt_cell(cell, FORWARD, *circuit.hops)
            elif exit_socket:
                self.encrypt_cell(cell, BACKWARD, exit_socket.hop)
            elif relay:
                if relay.rendezvous_relay:
                    self.encrypt_cell(cell, BACKWARD, relay.hop)
                else:
                    # We should only get here directly after a created message has been accepted.
                    other = self.relays[relay.circuit_id]
                    self.encrypt_cell(cell, other.direction, other.hop)
        except CryptoException as e:
            self.logger.warning(str(e))
            return None

        return cell

    def incoming_crypto(self, cell: CellPayload) -> CellPayload | None:
        """
        Decrypt a CellPayload using the SessionKeys currently available in the routing table.
        """
        circuit_id = cell.circuit_id
        circuit = self.circuits.get(circuit_id, None)
        exit_socket = self.exit_sockets.get(circuit_id, None)

        if not circuit and not exit_socket and not cell.plaintext:
            self.logger.debug("Got encrypted cell from unknown circuit %d", circuit_id)
            return None

        try:
            if exit_socket:
                self.decrypt_cell(cell, FORWARD, exit_socket.hop)
            elif circuit:
                self.decrypt_cell(cell, BACKWARD, *circuit.hops)
                if circuit.hs_session_keys:
                    direction = FORWARD if circuit.ctype == CIRCUIT_TYPE_RP_DOWNLOADER else BACKWARD
                    self.decrypt_cell(cell, direction, Hop(circuit.hop.peer, circuit.hs_session_keys))
        except CryptoException as e:
            self.logger.debug(str(e))
            return None
        return cell

    def encrypt_cell(self, cell: CellPayload, direction: int, *hops: Hop) -> None:
        """
        Encrypt a given cell.

        :raises CryptoException: if encryption failed.
        """
        if cell.plaintext:
            return

        for layer, hop in enumerate(reversed(hops)):
            if not hop.keys:
                msg = f"Missing keys for circuit {cell.circuit_id} (layer {layer + 1}/{len(hops)})"
                raise CryptoException(msg)

            try:
                cell.message = hop.keys.encrypt_str(cell.message, direction)
            except ValueError as e:
                msg = f"Failed to encrypt cell for {cell.circuit_id} (dir {direction}) (layer {layer + 1}/{len(hops)})"
                raise CryptoException(msg) from e

    def decrypt_cell(self, cell: CellPayload, direction: int, *hops: Hop) -> None:
        """
        Decrypt a given cell.

        :raises CryptoException: if decryption failed.
        """
        if cell.plaintext:
            return

        for layer, hop in enumerate(hops):
            if hop.keys is None:
                msg = f"Missing session keys for {cell.circuit_id} (layer {layer + 1}/{len(hops)})"
                raise CryptoException(msg)

            try:
                cell.message = hop.keys.decrypt_str(cell.message, direction)
            except ValueError as e:
                msg = f"Failed to decrypt cell for {cell.circuit_id} (dir {direction}) (layer {layer + 1}/{len(hops)})"
                raise CryptoException(msg) from e


class TunnelCrypto(ECCrypto):
    """
    Add Diffie-Hellman key establishment logic to ECCrypto.
    """

    def __init__(self) -> None:
        """
        Create a new handler for Tunnel encryption and decryption.
        """
        super().__init__()
        self.key: PrivateKey | None = None

    def initialize(self, key: PrivateKey) -> None:
        """
        Make this ECCrypto fit for key establishment based on the given public key.
        """
        self.key = key
        assert isinstance(self.key, PrivateKey), type(self.key)

    def is_key_compatible(self, key: PublicKey) -> bool:
        """
        Whether the given key is a ``PublicKey`` instance.
        """
        return key.curve_name() == "curve25519"

    def generate_diffie_secret(self) -> tuple[PrivateKey, bytes]:
        """
        Create a new private-public keypair.
        """
        tmp_key = self.generate_key("curve25519")
        return tmp_key, tmp_key.get_crypt_pk()

    def generate_diffie_shared_secret(self, dh_received: bytes, key: PrivateKey | None = None) -> tuple[bytes, bytes, bytes]:
        """
        Generate the shared secret from the received string and the given key.
        """
        if key is None:
            key = self.key
        if key is None:
            raise CryptoException

        tmp_key = OpenSSLSK.generate("curve25519")
        shared_secret = (tmp_key.diffie_hellman(dh_received) +
                         key.diffie_hellman(dh_received))

        crypt_pk = tmp_key.get_crypt_pk()
        auth = crypto_auth(shared_secret[:32], crypt_pk)

        return shared_secret, crypt_pk, auth

    @staticmethod
    def verify_and_generate_shared_secret(dh_secret: PrivateKey, dh_received: bytes, auth: bytes,
                                          b: bytes) -> bytes:
        """
        Generate the shared secret based on the response to the shared string and our own key.
        """
        s1 = dh_secret.diffie_hellman(dh_received)
        s2 = dh_secret.diffie_hellman(b)
        shared_secret = s1 + s2

        if not crypto_auth_verify(auth, shared_secret[:32], dh_received):
            raise CryptoException

        return shared_secret

    @staticmethod
    def generate_session_keys(shared_secret: bytes) -> SessionKeys:
        """
        Expand a shared secret into session keys using HKDF-SHA256.
        """
        return _generate_session_keys(shared_secret)
