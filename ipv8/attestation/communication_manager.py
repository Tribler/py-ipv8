from __future__ import annotations

import asyncio
import base64
import json
import os
from typing import Dict, Tuple, cast

from ..keyvault.crypto import ECCrypto
from ..messaging.anonymization.endpoint import TunnelEndpoint
from ..messaging.anonymization.hidden_services import HiddenTunnelCommunity
from ..types import IPv8, Peer, PrivateKey
from ..util import succeed
from .identity.community import IdentityCommunity, create_community
from .identity.manager import IdentityManager
from .wallet.community import AttestationCommunity, AttestationSettings

AttributePointer = Tuple[Peer, str]  # Backward compatibility: Python >= 3.9 can use ``tuple[Peer, str]``
MetadataDict = Dict[str, str]  # Backward compatibility: Python >= 3.9 can use ``dict[str, str]``


class CommunicationChannel:
    """
    A communication channel for business and proving logic of a single pseudonym.
    """

    def __init__(self, attestation_community: AttestationCommunity, identity_community: IdentityCommunity) -> None:
        """
        Create a channel through the given attestation (proving) and identity (business) overlays.
        """
        super().__init__()
        self.attestation_overlay = attestation_community
        self.identity_overlay = identity_community

        self.attestation_requests: dict[AttributePointer, tuple[asyncio.Future, str]] = {}
        self.verify_requests: dict[AttributePointer, asyncio.Future] = {}
        self.verification_output: dict[bytes, list[tuple[bytes, float | None]]] = {}
        self.attestation_metadata: dict[AttributePointer, MetadataDict] = {}

        self.attestation_overlay.set_attestation_request_callback(self.on_request_attestation)
        self.attestation_overlay.set_attestation_request_complete_callback(self.on_attestation_complete)
        self.attestation_overlay.set_verify_request_callback(self.on_verify_request)

    @property
    def public_key_bin(self) -> bytes:
        """
        Get the public key of our pseudonym in bytes .
        """
        return self.identity_overlay.my_peer.public_key.key_to_bin()

    @property
    def peers(self) -> list[Peer]:
        """
        List all the business logic peers for our pseudonym.
        """
        return self.identity_overlay.get_peers()

    @property
    def schemas(self) -> list[str]:
        """
        List all the identity formats we support.
        """
        return list(self.attestation_overlay.schema_manager.formats.keys())

    def on_request_attestation(self, peer: Peer, attribute_name: str,
                               metadata: MetadataDict) -> asyncio.Future:
        """
        Return the measurement of an attribute for a certain peer.
        """
        future: asyncio.Future = asyncio.Future()
        self.attestation_requests[(peer, attribute_name)] = (future, json.dumps(metadata))
        self.attestation_metadata[(peer, attribute_name)] = metadata
        return future

    def on_attestation_complete(self, for_peer: Peer, attribute_name: str, attribute_hash: bytes,
                                id_format: str, from_peer: Peer | None = None) -> None:
        """
        Callback for when an attestation has been completed for another peer.
        We can now sign for it.
        """
        metadata = self.attestation_metadata.get((for_peer, attribute_name), None)
        if for_peer == self.identity_overlay.my_peer:
            if from_peer == self.identity_overlay.my_peer:
                self.identity_overlay.self_advertise(attribute_hash, attribute_name, id_format, metadata)
            else:
                self.identity_overlay.request_attestation_advertisement(cast(Peer, from_peer),
                                                                        attribute_hash, attribute_name,
                                                                        id_format, metadata)
        else:
            self.identity_overlay.add_known_hash(attribute_hash, attribute_name, for_peer.public_key.key_to_bin(),
                                                 metadata)

    def on_verify_request(self, peer: Peer, attribute_hash: bytes) -> asyncio.Future:
        """
        Return the measurement of an attribute for a certain peer.
        """
        metadata = self.identity_overlay.get_attestation_by_hash(attribute_hash)
        if not metadata:
            return succeed(None)
        attribute_name = json.loads(metadata.serialized_json_dict)["name"]
        future: asyncio.Future[bool] = asyncio.Future()
        self.verify_requests[(peer, attribute_name)] = future
        return future

    def on_verification_results(self, attribute_hash: bytes, values: list[float]) -> None:
        """
        Callback for when verification has concluded.
        """
        references = self.verification_output[attribute_hash]
        self.verification_output[attribute_hash] = [(references[i][0], values[i]) for i in range(len(references))]

    def _drop_identity_table_data(self) -> list[bytes]:
        """
        Remove all metadata from the identity community.

        :return: the list of attestation hashes which have been removed
        :rtype: [bytes]
        """
        database = self.identity_overlay.identity_manager.database
        attestation_hashes = [t.content_hash for t in database.get_tokens_for(self.identity_overlay.my_peer.public_key)]

        database.executescript("BEGIN TRANSACTION; "
                               "DELETE FROM Tokens WHERE public_key = ?; "
                               "DELETE FROM Metadata WHERE public_key = ?; "
                               "DELETE FROM Attestations WHERE public_key = ?; "
                               "COMMIT;",
                               (self.public_key_bin, self.public_key_bin, self.public_key_bin))
        database.commit()

        return attestation_hashes

    def _drop_attestation_table_data(self, attestation_hashes: list[bytes]) -> None:
        """
        Remove all attestation data (claim based keys and ZKP blobs) by list of attestation hashes.

        :param attestation_hashes: hashes to remove
        :type attestation_hashes: [bytes]
        :returns: None
        """
        if not attestation_hashes:
            return

        self.attestation_overlay.database.execute(("DELETE FROM %s"  # noqa: S608
                                                   % self.attestation_overlay.database.db_name)
                                                  + " WHERE hash IN ("
                                                  + ", ".join(c for c in "?" * len(attestation_hashes))
                                                  + ")",
                                                  attestation_hashes)
        self.attestation_overlay.database.commit()

    def remove(self) -> None:
        """
        Remove this pseudonym from existence.
        """
        self._drop_attestation_table_data(self._drop_identity_table_data())
        self.attestation_requests.clear()

    def get_my_attributes(self) -> dict[bytes, tuple[str, MetadataDict, list[bytes]]]:
        """
        Get the known attributes for our pseudonym.
        """
        return self.get_attributes(self.identity_overlay.my_peer)

    def get_attributes(self, peer: Peer) -> dict[bytes, tuple[str, MetadataDict, list[bytes]]]:
        """
        Get the known attributes of a given peer.
        """
        pseudonym = self.identity_overlay.identity_manager.get_pseudonym(peer.public_key)
        out = {}
        for credential in pseudonym.get_credentials():
            attestations = list(credential.attestations)
            attesters = [self.identity_overlay.identity_manager.database.get_authority(attestation)
                         for attestation in attestations]
            attribute_hash = pseudonym.tree.elements[credential.metadata.token_pointer].content_hash
            json_metadata = json.loads(credential.metadata.serialized_json_dict)
            out[attribute_hash] = (json_metadata["name"], json_metadata, attesters)
        return out

    def request_attestation(self, peer: Peer, attribute_name: str, id_format: str,
                            metadata: MetadataDict) -> None:
        """
        Request another peer to attest to our attribute.
        """
        key = self.attestation_overlay.get_id_algorithm(id_format).generate_secret_key()
        metadata.update({"id_format": id_format})
        self.attestation_metadata[(self.identity_overlay.my_peer, attribute_name)] = metadata
        self.attestation_overlay.request_attestation(peer, attribute_name, key, metadata)

    def attest(self, peer: Peer, attribute_name: str, value: bytes) -> None:
        """
        Attest to another peer's attribute (if it's value is what we expect).
        """
        outstanding = self.attestation_requests.pop((peer, attribute_name))
        outstanding[0].set_result(value)

    def import_blob(self, attribute_name: str, id_format: str, metadata: MetadataDict, value: bytes) -> None:
        """
        Import an external proof as a raw blob (advanced use only!).
        """
        metadata.update({"id_format": id_format})
        self.attestation_overlay.dump_blob(attribute_name, id_format, value, metadata)

    def allow_verification(self, peer: Peer, attribute_name: str) -> None:
        """
        Consent to verification of an attribute by a peer.
        """
        outstanding = self.verify_requests.pop((peer, attribute_name))
        outstanding.set_result(True)

    def disallow_verification(self, peer: Peer, attribute_name: str) -> None:
        """
        Do not consent to verification of an attribute by a peer.
        """
        outstanding = self.verify_requests.pop((peer, attribute_name))
        outstanding.set_result(False)

    def verify(self, peer: Peer, attribute_hash: bytes, reference_values: list[bytes], id_format: str) -> None:
        """
        Play out the Zero-Knowledge Proof of a given attribute hash for a peer.
        """
        self.verification_output[attribute_hash] = [(v, None) for v in reference_values]
        self.attestation_overlay.verify_attestation_values(peer.address, attribute_hash, reference_values,
                                                           self.on_verification_results, id_format)


class PseudonymFolderManager:
    """
    Perform file management of pseudonyms.
    """

    def __init__(self, directory: str) -> None:
        """
        Manage/store pseudonyms in a given directory.

        :param directory: the directory to store pseudonyms
        :returns: None
        """
        self.pseudonym_folder = directory
        self.crypto = ECCrypto()

    def get_or_create_private_key(self, name: str) -> PrivateKey:
        """
        Get the private key for a pseudonym by either reading it or generating it. In the latter case, write to a file.

        :param name: the name of the pseudonym to load or generate a private key for.
        :return: the private key for the given pseudonym.
        """
        os.makedirs(self.pseudonym_folder, exist_ok=True)
        pseudonym_file = os.path.join(self.pseudonym_folder, name)
        if os.path.exists(pseudonym_file):
            with open(pseudonym_file, 'rb') as file_handle:
                private_key = self.crypto.key_from_private_bin(file_handle.read())
        else:
            private_key = self.crypto.generate_key("curve25519")
            with open(pseudonym_file, 'wb') as file_handle:
                file_handle.write(private_key.key_to_bin())
        return private_key

    def remove_pseudonym_file(self, name: str) -> None:
        """
        Remove a pseudonym file by its name.

        :param name: the name of the pseudonym file to remove.
        :returns: None
        """
        pseudonym_file = os.path.join(self.pseudonym_folder, name)
        if os.path.exists(pseudonym_file):
            os.remove(pseudonym_file)

    def list_pseudonym_files(self) -> list[str]:
        """
        List all the pseudonym files in our pseudonym directory.

        :return: the list of pseudonym names.
        """
        if not os.path.exists(self.pseudonym_folder):
            return []
        return os.listdir(self.pseudonym_folder)


class CommunicationManager:
    """
    Manager of pseudonym managers, usually operated from the REST API by a user app.
    """

    def __init__(self, ipv8_instance: IPv8, pseudonym_folder: str = "pseudonyms",
                 working_directory: str | None = None) -> None:
        """
        Manage pseudonyms in the given folder.
        """
        super().__init__()

        self.ipv8_instance = ipv8_instance
        self.channels: dict[bytes, CommunicationChannel] = {}

        self.name_to_channel: dict[str, CommunicationChannel] = {}

        self.crypto = ECCrypto()

        loaded_community = ipv8_instance.get_overlay(IdentityCommunity)
        self.identity_manager = (None if loaded_community is None
                                 else cast(IdentityCommunity, loaded_community).identity_manager)

        if working_directory is None:
            working_directory = ipv8_instance.configuration.get("working_directory", ".")

        self.working_directory = working_directory
        self.pseudonym_folder_manager = PseudonymFolderManager(os.path.join(self.working_directory, pseudonym_folder))

    def lazy_identity_manager(self) -> IdentityManager:
        """
        Lazy load the IdentityManager.
        """
        if self.identity_manager is None:
            self.identity_manager = IdentityManager(self.working_directory if self.working_directory == ":memory:"
                                                    else os.path.join(self.working_directory, "sqlite", "identity.db"))
        return self.identity_manager

    async def load(self, name: str, rendezvous_token: str | None = None) -> CommunicationChannel:
        """
        Load a pseudonym.
        """
        if name in self.name_to_channel:
            return self.name_to_channel[name]

        private_key = self.pseudonym_folder_manager.get_or_create_private_key(name)

        public_key = private_key.pub().key_to_bin()
        if public_key not in self.channels:
            tunnel_community = self.ipv8_instance.get_overlay(HiddenTunnelCommunity)
            decoded_rendezvous_token = (base64.b64decode(rendezvous_token.encode())
                                        if rendezvous_token is not None else None)
            identity_overlay = await create_community(private_key, self.ipv8_instance, self.lazy_identity_manager(),
                                                      working_directory=self.working_directory,
                                                      anonymize=tunnel_community is not None,
                                                      rendezvous_token=decoded_rendezvous_token)
            settings = AttestationSettings(my_peer=identity_overlay.my_peer, endpoint=identity_overlay.endpoint,
                                           network=identity_overlay.network, working_directory=self.working_directory,
                                           anonymize=tunnel_community is not None)
            attestation_overlay = AttestationCommunity(settings)
            cast(TunnelEndpoint, identity_overlay.endpoint).set_tunnel_community(tunnel_community)
            self.channels[public_key] = CommunicationChannel(attestation_overlay, identity_overlay)
            self.name_to_channel[name] = self.channels[public_key]

        return self.name_to_channel[name]

    async def unload(self, name: str) -> None:
        """
        Unload a pseudonym.
        """
        if name in self.name_to_channel:
            communication_channel = self.name_to_channel.pop(name)
            self.channels.pop(communication_channel.public_key_bin)
            await self.ipv8_instance.unload_overlay(communication_channel.identity_overlay)
            await communication_channel.attestation_overlay.unload()
            communication_channel.identity_overlay.endpoint.close()

    async def remove(self, name: str) -> None:
        """
        Remove a pseudonym from existence by name.
        """
        if name in self.name_to_channel:
            self.name_to_channel.pop(name).remove()
            await self.unload(name)
            self.pseudonym_folder_manager.remove_pseudonym_file(name)

    async def shutdown(self) -> None:
        """
        Close down all communication.
        """
        for name in list(self.name_to_channel):
            await self.unload(name)

    def list_names(self) -> list[str]:
        """
        List all known pseudonyms.
        """
        return self.pseudonym_folder_manager.list_pseudonym_files()

    def list_loaded(self) -> list[str]:
        """
        List all loaded pseudonyms by name.
        """
        return [name for name in self.list_names() if name in self.name_to_channel]
