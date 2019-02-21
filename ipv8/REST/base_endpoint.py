from __future__ import absolute_import

from twisted.web import resource
from twisted.web.resource import _computeAllowedMethods


class BaseEndpoint(resource.Resource, object):
    """
    The base endpoint from which all other endpoints should extend to make them compatible with Cross-Origin Resource
    Sharing requests.
    """
    def __init__(self):
        resource.Resource.__init__(self)
        object.__init__(self)

    def render_OPTIONS(self, request):
        """
        This methods renders the HTTP OPTIONS method used for returning available HTTP methods and Cross-Origin Resource
        Sharing preflight request checks.
        """
        # Check if the allowed methods were explicitly set, otherwise compute them automatically
        try:
            allowed_methods = self.allowedMethods
        except AttributeError:
            allowed_methods = _computeAllowedMethods(self)
        allowed_methods_string = " ".join(allowed_methods)

        # Set the header for the HTTP OPTION method
        request.setHeader(b'Allow', allowed_methods_string)

        # Set the required headers for preflight checks
        if request.getHeader(b'Access-Control-Request-Headers'):
            request.setHeader(b'Access-Control-Allow-Headers', request.getHeader(b'Access-Control-Request-Headers'))
        request.setHeader(b'Access-Control-Allow-Methods', allowed_methods_string)
        request.setHeader(b'Access-Control-Max-Age', 86400)

        # Return empty body
        return b""
