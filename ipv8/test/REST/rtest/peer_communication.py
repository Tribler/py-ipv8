
from abc import abstractmethod


class PostStyleRequests(object):

    @abstractmethod
    def make_attestation_request(self, param_dict):
        """
        Generate an attestation request

        :param param_dict: the request's arguments
        :return: None
        """
        pass

    @abstractmethod
    def make_attest(self, param_dict):
        """
        Generate an attestation

        :param param_dict: the request's arguments
        :return: None
        """
        pass

    @abstractmethod
    def make_verify(self, param_dict):
        """
        Generate an attestation verification request

        :param param_dict: the request's arguments
        :return: None
        """
        pass


class GetStyleRequests(object):

    @abstractmethod
    def make_outstanding(self, param_dict):
        """
        Generate a request asking for the outstanding attestation requests

        :param param_dict: the request's arguments
        :return: None
        """
        pass

    @abstractmethod
    def make_verification_output(self, param_dict):
        """
        Generate a request asking for the outputs of the verification processes

        :param param_dict: the request's arguments
        :return: None
        """
        pass

    @abstractmethod
    def make_peers(self, param_dict):
        """
        Generate a request asking for the known peers in the network

        :param param_dict: the request's arguments
        :return: None
        """
        pass

    @abstractmethod
    def make_attributes(self, param_dict):
        """
        Generate a request asking for the known peers in the network

        :param param_dict: the request's arguments
        :return: None
        """
        pass

    @abstractmethod
    def make_drop_identity(self, param_dict):
        """
        Generate a request for dropping an identity

        :param param_dict: the request's arguments
        :return: None
        """
        pass


class RequestException(Exception):
    """
    Custom exception used to model request errors
    """
