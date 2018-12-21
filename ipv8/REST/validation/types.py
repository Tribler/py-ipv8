import codecs

from six import integer_types


class JSONType(object):

    def __init__(self, json_type, python_types):
        super(JSONType, self).__init__()
        self.json_type = json_type
        self.python_types = python_types

    def matches(self, python_variable):
        return type(python_variable) in self.python_types


class JSONStringType(JSONType):

    def __init__(self, json_type, python_types, encoding):
        super(JSONStringType, self).__init__(json_type, python_types)
        self.encoding = encoding

    def matches(self, python_variable):
        super_matches = super(self, JSONStringType).matches(python_variable)
        if super_matches:
            try:
                codecs.decode(python_variable, self.encoding)
            except ValueError:
                super_matches = False
        return super_matches

class JSONTupleType(JSONType):

    def __init__(self, *inner_types):
        super(JSONTupleType, self).__init__("", tuple)
        self.inner_types = inner_types

    def matches(self, python_variable):
        if not isinstance(python_variable, tuple):
            return False
        from .matching import matches
        return all(matches(python_variable[i], self.inner_types[i]) for i in range(len(python_variable)))


class OptionalKey(JSONStringType):

    def __init__(self, key):
        super(OptionalKey, self).__init__("string (ascii)", str, 'ascii')
        self.key = key

    def matches(self, python_variable):
        return super(OptionalKey, self).matches(python_variable) and python_variable == self.key

    def __str__(self):
        return self.key


BOOLEAN_TYPE = JSONType("boolean", bool)
NUMBER_TYPE = JSONType("number", integer_types + (float, ))
STR_TYPE = {
    "ASCII": JSONStringType("string (ascii)", str, 'ascii'),
    "BASE64": JSONStringType("string (base64)", str, 'base64'),
    "HEX": JSONStringType("string (hex)", str, 'hex'),
    "UTF-8": JSONStringType("string (utf-8)", str, 'utf-8'),
}
TUPLE_TYPE = JSONTupleType
UNKNOWN_OBJECT = JSONType("{...}", dict)
