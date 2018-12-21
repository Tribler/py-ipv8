from collections import namedtuple
from functools import wraps
from json import loads

from twisted.web import http
from twisted.web.server import NOT_DONE_YET

from ..documentation.opcodereader import pretty_str_simple_lambda
from .matching import matches, sanitize_request


postcondition = namedtuple("postcondition", ["response_code", "conditional_lambda"])
postcondition.__hash__ = lambda self: self.conditional_lambda.__hash__()


def assert_api_spec(func):
    """
    Inject a `restapi` dictionary into a function, if it is not already there.

    :param func: the function to inject into
    :type func: types.FunctionType
    :return: the wrapped function, the dictionary
    :rtype: types.FunctionType, dict
    """
    # types.LambdaType is full of lies, we can't use it here
    out = func if func.func_name == "<lambda>" else lambda self, request: request_handler_wrapper(func, self, request)
    restapi_container = out.func_closure[0].cell_contents # This is `func`, which may have been set by someone else
    if not hasattr(restapi_container, "restapi"):
        setattr(restapi_container, "restapi", {"preconditions": {}, "postconditions": {}})
    return out, restapi_container.restapi


def request_handler_wrapper(func, self, request):
    """
    The wrapper around a request handler (render_GET, etc.).
    This checks the preconditions and postconditions around the execution of the actual handler.

    :param func: the request handler function
    :type func: types.FunctionType
    :param self: the `self` argument for the handler method
    :type self: twisted.web.resource.Resource
    :param request: the request for the handler
    :type request: twisted.web.http.Request
    :except RuntimeError: if the preconditions or the postconditions were violated
    :return: the result of running func on the request
    """
    sanitized_request = sanitize_request(request)
    # Check preconditions
    for option in sanitized_request:
        check = matches(sanitized_request[option], func.restapi["preconditions"][option])
        if not check:
            raise RuntimeError("Input for option %s of %s failed precondition check!" % (option, str(func)))
    def check_postconditions(returned_result):
        for spec in func.restapi["postconditions"]:
            response_code, conditional_lambda = spec
            if not isinstance(response_code, list):
                response_code = [response_code]
            if request.code in response_code and conditional_lambda(sanitized_request):
                check = matches(loads(returned_result), func.restapi["postconditions"][conditional_lambda])
                if not check:
                    raise RuntimeError("Postcondition for %s using lambda %s failed!" %
                                       (str(func), pretty_str_simple_lambda(conditional_lambda)))
    # Run function
    result = func(self, request)
    if result == NOT_DONE_YET:
        old_write = request.write

        @wraps(old_write)
        def new_write(request_self, data):
            check_postconditions(data)
            old_write(request_self, data)
            request.write = old_write
        request.write = new_write
    else:
        check_postconditions(result)
    return result


def RESTInput(option, jsontype):
    def wrapper(f):
        out, restapi = assert_api_spec(f)
        restapi["preconditions"][option] = jsontype
        return out
    return wrapper


def RESTOutput(conditional_lambda, output_format, response_code=http.OK):
    def wrapper(f):
        out, restapi = assert_api_spec(f)
        restapi["postconditions"][postcondition(response_code, conditional_lambda)] = output_format
        return out
    return wrapper


__all__ = ["RESTInput", "RESTOutput"]
