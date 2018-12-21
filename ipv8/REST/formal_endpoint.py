from six.moves import xrange
from twisted.web import resource

from .documentation.apireader import create_document_from_apis


METHOD_PREFIX = "render_"


def sanitize_docstring(raw_docstring):
    if not raw_docstring:
        return ""
    lines = raw_docstring.split("\n")
    if lines:
        min_prefix = None
        for line in lines:
            if line.strip():
                if min_prefix:
                    min_prefix = min(min_prefix, len(line) - len(line.lstrip()))
                else:
                    min_prefix = len(line) - len(line.lstrip())
        for i in xrange(len(lines)):
            lines[i] = lines[i][min_prefix:] if line else line
    return "\n".join(lines)


class FormalEndpoint(object, resource.Resource):

    def __init__(self):
        object.__init__(self)
        resource.Resource.__init__(self)

    def generate_documentation(self, absolute_path=[]):
        for relative_path, child in self.children.items():
            if isinstance(child, FormalEndpoint):
                child.generate_documentation(absolute_path + [relative_path])
        api_spec = {}
        for method in dir(self):
            # We first need to check startswith or the hasattr/getattr might fail.
            if method.startswith(METHOD_PREFIX) and getattr(self, method).im_func.func_name == "<lambda>":
                actual_function = getattr(self, method).im_func.func_closure[0].cell_contents
                specification = actual_function.restapi
                http_method = method[len(METHOD_PREFIX):]
                if http_method not in api_spec:
                    api_spec[http_method] = ([], sanitize_docstring(actual_function.__doc__))
                api_spec[http_method][0].append(specification)
        # TODO DEBUG
        import os
        with open(os.path.expanduser("~/Documents/testing/" + self.__class__.__name__ + ".html"), "w") as f:
            f.write(create_document_from_apis(api_spec, self.__class__.__name__, "/%s" % "/".join(absolute_path),
                                            self.__class__.__doc__))
        print "Finished", self.__class__.__name__

