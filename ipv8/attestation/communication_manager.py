import asyncio
import json
import os
import typing

from .identity.community import IdentityCommunity, create_community
from .identity.manager import IdentityManager
from .wallet.community import AttestationCommunity
from ..keyvault.crypto import ECCrypto
from ..messaging.anonymization.hidden_services import HiddenTunnelCommunity
from ..util import succeed


class CommunicationChannel(object):

    def __init__(self, attestation_community, identity_community):
        super(CommunicationChannel, self).__init__()
        self.attestation_overlay = attestation_community
        self.identity_overlay = identity_community

        self.attestation_requests = {}
        self.verify_requests = {}
        self.verification_output = {}
        self.attestation_metadata = {}

        self.attestation_overlay.set_attestation_request_callback(self.on_request_attestation)
        self.attestation_overlay.set_attestation_request_complete_callback(self.on_attestation_complete)
        self.attestation_overlay.set_verify_request_callback(self.on_verify_request)

    @property
    def public_key_bin(self):
        return self.identity_overlay.my_peer.public_key.key_to_bin()

    @property
    def peers(self):
        return self.identity_overlay.get_peers()

    @property
    def schemas(self):
        return list(self.attestation_overlay.schema_manager.formats.keys())

    def on_request_attestation(self, peer, attribute_name, metadata):
        """
        Return the measurement of an attribute for a certain peer.
        """
        future = asyncio.Future()
        self.attestation_requests[(peer, attribute_name)] = (future, json.dumps(metadata))
        self.attestation_metadata[(peer, attribute_name)] = metadata
        return future

    def on_attestation_complete(self, for_peer, attribute_name, attribute_hash, id_format, from_peer=None):
        """
        Callback for when an attestation has been completed for another peer.
        We can now sign for it.
        """
        metadata = self.attestation_metadata.get((for_peer, attribute_name), None)
        if for_peer == self.identity_overlay.my_peer:
            if from_peer == self.identity_overlay.my_peer:
                self.identity_overlay.self_advertise(attribute_hash, attribute_name, id_format, metadata)
            else:
                self.identity_overlay.request_attestation_advertisement(from_peer, attribute_hash, attribute_name,
                                                                        id_format, metadata)
        else:
            self.identity_overlay.add_known_hash(attribute_hash, attribute_name, for_peer.public_key.key_to_bin(),
                                                 metadata)

    def on_verify_request(self, peer, attribute_hash):
        """
        Return the measurement of an attribute for a certain peer.
        """
        metadata = self.identity_overlay.get_attestation_by_hash(attribute_hash)
        if not metadata:
            return succeed(None)
        attribute_name = json.loads(metadata.serialized_json_dict)["name"]
        future = asyncio.Future()
        self.verify_requests[(peer, attribute_name)] = future
        return future

    def on_verification_results(self, attribute_hash, values):
        """
        Callback for when verification has concluded.
        """
        references = self.verification_output[attribute_hash]
        out = []
        for i in range(len(references)):
            out.append((references[i][0] if isinstance(references[i], tuple) else references[i], values[i]))
        self.verification_output[attribute_hash] = out

    def _drop_identity_table_data(self):
        """
        Remove all metadata from the identity community.

        :return: the list of attestation hashes which have been removed
        :rtype: [database_blob]
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

    def _drop_attestation_table_data(self, attestation_hashes):
        """
        Remove all attestation data (claim based keys and ZKP blobs) by list of attestation hashes.

        :param attestation_hashes: hashes to remove
        :type attestation_hashes: [database_blob]
        :returns: None
        """
        if not attestation_hashes:
            return

        self.attestation_overlay.database.execute(("DELETE FROM %s" % self.attestation_overlay.database.db_name)
                                                  + " WHERE hash IN ("
                                                  + ", ".join(c for c in "?" * len(attestation_hashes))
                                                  + ")",
                                                  attestation_hashes)
        self.attestation_overlay.database.commit()

    def remove(self):
        """
        Remove this pseudonym from existence.
        """
        self._drop_attestation_table_data(self._drop_identity_table_data())
        self.attestation_requests.clear()

    def get_my_attributes(self):
        return self.get_attributes(self.identity_overlay.my_peer)

    def get_attributes(self, peer):
        pseudonym = self.identity_overlay.identity_manager.get_pseudonym(peer.public_key)
        out = {}
        for credential in pseudonym.get_credentials():
            attestations = list(credential.attestations)
            attesters = []
            for attestation in attestations:
                attesters.append(self.identity_overlay.identity_manager.database.get_authority(attestation))
            attribute_hash = pseudonym.tree.elements[credential.metadata.token_pointer].content_hash
            json_metadata = json.loads(credential.metadata.serialized_json_dict)
            out[attribute_hash] = (json_metadata["name"], json_metadata, attesters)
        return out

    def request_attestation(self, peer, attribute_name, id_format, metadata):
        key = self.attestation_overlay.get_id_algorithm(id_format).generate_secret_key()
        metadata.update({"id_format": id_format})
        self.attestation_metadata[(self.identity_overlay.my_peer, attribute_name)] = metadata
        self.attestation_overlay.request_attestation(peer, attribute_name, key, metadata)

    def attest(self, peer, attribute_name, value):
        outstanding = self.attestation_requests.pop((peer, attribute_name))
        outstanding[0].set_result(value)

    def import_blob(self, attribute_name, id_format, metadata, value):
        metadata.update({"id_format": id_format})
        self.attestation_overlay.dump_blob(attribute_name, id_format, value, metadata)

    def allow_verification(self, peer, attribute_name):
        outstanding = self.verify_requests.pop((peer, attribute_name))
        outstanding.set_result(True)

    def disallow_verification(self, peer, attribute_name):
        outstanding = self.verify_requests.pop((peer, attribute_name))
        outstanding.set_result(False)

    def verify(self, peer, attribute_hash, reference_values, id_format):
        self.verification_output[attribute_hash] = \
            [(v, None) for v in reference_values]
        self.attestation_overlay.verify_attestation_values(peer.address, attribute_hash, reference_values,
                                                           self.on_verification_results, id_format)


class CommunicationManager(object):

    def __init__(self, ipv8_instance, pseudonym_folder: str = "pseudonyms", working_directory=None):
        super(CommunicationManager, self).__init__()

        self.ipv8_instance = ipv8_instance
        self.channels = {}

        self.pseudonym_folder = pseudonym_folder
        self.name_to_channel = {}

        self.crypto = ECCrypto()

        loaded_community = ipv8_instance.get_overlay(IdentityCommunity)
        if loaded_community is not None:
            self.identity_manager = loaded_community.identity_manager
        else:
            if working_directory is None:
                working_directory = ipv8_instance.configuration.get("working_directory", ".")
            self.identity_manager = IdentityManager(working_directory if working_directory == ":memory:"
                                                    else os.path.join(working_directory, "sqlite", "identity.db"))

        self.working_directory = working_directory

    async def load(self, name: str) -> CommunicationChannel:
        """
        Load a pseudonym.
        """
        if name in self.name_to_channel:
            return self.name_to_channel[name]

        os.makedirs(self.pseudonym_folder, exist_ok=True)
        pseudonym_file = os.path.join(self.pseudonym_folder, name)
        if os.path.exists(pseudonym_file):
            with open(pseudonym_file, 'rb') as file_handle:
                private_key = self.crypto.key_from_private_bin(file_handle.read())
        else:
            private_key = self.crypto.generate_key("curve25519")
            with open(pseudonym_file, 'wb') as file_handle:
                file_handle.write(private_key.key_to_bin())

        public_key = private_key.pub().key_to_bin()
        if public_key not in self.channels:
            tunnel_community = self.ipv8_instance.get_overlay(HiddenTunnelCommunity)
            identity_overlay = await create_community(private_key, self.ipv8_instance, self.identity_manager,
                                                      working_directory=self.working_directory,
                                                      anonymize=tunnel_community is not None)
            attestation_overlay = AttestationCommunity(identity_overlay.my_peer, identity_overlay.endpoint,
                                                       identity_overlay.network,
                                                       working_directory=self.working_directory,
                                                       anonymize=tunnel_community is not None)
            identity_overlay.endpoint.set_tunnel_community(tunnel_community)
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
            pseudonym_file = os.path.join(self.pseudonym_folder, name)
            if os.path.exists(pseudonym_file):
                os.remove(pseudonym_file)

    def list_names(self) -> typing.List[str]:
        """
        List all known pseudonyms.
        """
        if not os.path.exists(self.pseudonym_folder):
            return []
        return os.listdir(self.pseudonym_folder)

    def list_loaded(self) -> typing.List[str]:
        """
        List all loaded pseudonyms by name.
        """
        return [name for name in self.list_names() if name in self.name_to_channel]
