from logging import error

from .types import JSONType, OptionalKey


def matches(data, pattern):
    """
    Match data (python struct) to a pattern.

    Patterns can be:
     - 2-tuples, containing (other pattern, documentation)
     - JSONType instances (generally representing numbers or strings)
     - dict, list
    """
    if isinstance(pattern, tuple):
        # We don't care about documentation, throw it out and start again
        return matches(data, pattern[0])
    if isinstance(pattern, JSONType):
        return pattern.matches(data)
    elif type(data) != type(pattern):
        error("Expected %s to be of type %s", str(data), str(type(pattern)))
        return False
    if isinstance(pattern, dict):
        if all(isinstance(k, (OptionalKey, str)) for k in pattern):
            # Strict dict matching (dict has specific keys)
            # e.g. {"age": NUMBER_TYPE} matches {"age": 1}
            #      {"age": NUMBER_TYPE} does not match {}, {"no": 1} nor {"age": "1"}
            given_keys = set(data.keys())
            obligatory_keys = {key for key in pattern.keys() if not isinstance(key, OptionalKey)}
            optional_keys = {key.key for key in pattern.keys() if isinstance(key, OptionalKey)}
            remaining_obligatory_keys = obligatory_keys - given_keys
            if remaining_obligatory_keys or (given_keys - obligatory_keys - optional_keys):
                error("Pattern expects keys %s, got %s", str(pattern.keys()), str(data))
                return False
            else:
                return all(matches(data[k], pattern[k]) for k in data)
        else:
            # Anonymous mapping (keys match a pattern)
            # e.g. {STR_TYPE["ASCII"]: NUMBER_TYPE} -> {"age": 1, "something": 2}
            if len(pattern) > 1:
                # We could support mixed types, but it makes the formats hard to read and harder to check
                # Generally this would imply bad API design, so we don't even allow it :)
                error("Illegal pattern. Pattern supplies multiple patterns to match to: %s", str(pattern.keys()))
                return False
            match_key = pattern.keys()[0]
            if all(matches(k, match_key) for k in data):
                return all(matches(data[k], pattern[match_key]) for k in data)
            else:
                error("Found keys %s, which do not match pattern %s",
                      str([k for k in data if not matches(k, match_key)]), str(pattern[match_key]))
                return False
    # List (or set)
    return all(matches(data[k], list(pattern)[0]) for k in data)



def sanitize_request(request):
    """
    We normally expect a key -> value mapping, so we normalize to this.
    Only in case of a key mapping to multiple values do we return the array.
    """
    mapping = request.args
    for k, v in mapping.items():
        if len(v) == 1:
            mapping[k] = v[0]
    return mapping


__all__ = ["matches", "sanitize_request"]
