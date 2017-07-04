from random import random
import logging

from twisted.internet import reactor
from twisted.python.threadable import isInIOThread

from .taskmanager import TaskManager


class NumberCache(object):

    def __init__(self, request_cache, prefix, number):
        assert isinstance(number, (int, long)), type(number)
        assert isinstance(prefix, unicode), type(prefix)

        super(NumberCache, self).__init__()
        self._logger = logging.getLogger(self.__class__.__name__)

        if request_cache.has(prefix, number):
            raise RuntimeError("This number is already in use '%s'" % number)

        self._prefix = prefix
        self._number = number

    @property
    def prefix(self):
        return self._prefix

    @property
    def number(self):
        return self._number

    @property
    def timeout_delay(self):
        return 10.0

    def on_timeout(self):
        raise NotImplementedError()

    def __str__(self):
        return "<%s %s-%d>" % (self.__class__.__name__, self.prefix, self.number)


class RandomNumberCache(NumberCache):

    def __init__(self, request_cache, prefix):
        assert isinstance(prefix, unicode), type(prefix)

        # find an unclaimed identifier
        number = RandomNumberCache.find_unclaimed_identifier(request_cache, prefix)
        super(RandomNumberCache, self).__init__(request_cache, prefix, number)

    @classmethod
    def find_unclaimed_identifier(cls, request_cache, prefix):
        for _ in xrange(1000):
            number = int(random() * 2 ** 16)
            if not request_cache.has(prefix, number):
                break
        else:
            raise RuntimeError("Could not find a number that isn't in use")

        return number


class SignatureRequestCache(RandomNumberCache):

    def __init__(self, request_cache, members, response_func, response_args, timeout):
        super(SignatureRequestCache, self).__init__(request_cache, u"signature-request")
        self.request = None
        # MEMBERS is a list containing all the members that should add their signature.  currently
        # we only support double signed messages, hence MEMBERS contains only a single Member
        # instance.
        self.members = members
        self.response_func = response_func
        self.response_args = response_args
        self._timeout_delay = timeout

    @property
    def timeout_delay(self):
        return self._timeout_delay

    def on_timeout(self):
        self._logger.debug("signature timeout")
        self.response_func(self, None, True, *self.response_args)


class IntroductionRequestCache(RandomNumberCache):

    @property
    def timeout_delay(self):
        # we will accept the response at most 10.5 seconds after our request
        return 10.5

    def __init__(self, community, helper_candidate):
        super(IntroductionRequestCache, self).__init__(community.request_cache, u"introduction-request")
        self.community = community
        self.helper_candidate = helper_candidate
        self.response_candidate = None
        self.puncture_candidate = None
        self._introduction_response_received = False
        self._puncture_received = False

    def on_timeout(self):
        if not self._introduction_response_received:
            # helper_candidate did not respond to a request message in this
            # community.  The obsolete candidates will be removed by the
            # dispersy_get_walk_candidate() in community.

            self._logger.debug("walker timeout for %s", self.helper_candidate)

            self.community.statistics.increase_msg_count(u"walk_failure", self.helper_candidate.sock_addr)
            self.community.dispersy.statistics.walk_failure_count += 1
            self.community.dispersy.statistics.dict_inc(u"walk_failure_dict", self.helper_candidate.sock_addr)

            # set the walk repsonse to be invalid
            self.helper_candidate.walk_response(-1.0)

    def _check_if_both_received(self):
        if self._introduction_response_received and self._puncture_received:
            self.community.request_cache.pop(self.prefix, self.number)

    def on_introduction_response(self):
        self._introduction_response_received = True
        self._check_if_both_received()

    def on_puncture(self):
        self._puncture_received = True
        self._check_if_both_received()


class RequestCache(TaskManager):

    def __init__(self):
        """
        Creates a new RequestCache instance.
        """
        super(RequestCache, self).__init__()

        assert isInIOThread(), "RequestCache must be used on the reactor's thread"

        self._logger = logging.getLogger(self.__class__.__name__)

        self._identifiers = dict()

    def add(self, cache):
        """
        Add CACHE into this RequestCache instance.

        Returns CACHE when CACHE.identifier was not yet added, otherwise returns None.
        """
        assert isInIOThread(), "RequestCache must be used on the reactor's thread"
        assert isinstance(cache, NumberCache), type(cache)
        assert isinstance(cache.number, (int, long)), type(cache.number)
        assert isinstance(cache.prefix, unicode), type(cache.prefix)
        assert isinstance(cache.timeout_delay, float), type(cache.timeout_delay)
        assert cache.timeout_delay > 0.0, cache.timeout_delay

        identifier = self._create_identifier(cache.number, cache.prefix)
        if identifier in self._identifiers:
            self._logger.error("add with duplicate identifier \"%s\"", identifier)
            return None

        else:
            self._logger.debug("add %s", cache)
            self._identifiers[identifier] = cache
            self.register_task(cache, reactor.callLater(cache.timeout_delay, self._on_timeout, cache))
            return cache

    def has(self, prefix, number):
        """
        Returns True when IDENTIFIER is part of this RequestCache.
        """
        assert isInIOThread(), "RequestCache must be used on the reactor's thread"
        assert isinstance(number, (int, long)), type(number)
        assert isinstance(prefix, unicode), type(prefix)
        return self._create_identifier(number, prefix) in self._identifiers

    def get(self, prefix, number):
        """
        Returns the Cache associated with IDENTIFIER when it exists, otherwise returns None.
        """
        assert isInIOThread(), "RequestCache must be used on the reactor's thread"
        assert isinstance(number, (int, long)), type(number)
        assert isinstance(prefix, unicode), type(prefix)
        return self._identifiers.get(self._create_identifier(number, prefix))

    def pop(self, prefix, number):
        """
        Returns the Cache associated with IDENTIFIER, and removes it from this RequestCache, when it exists, otherwise
        raises a KeyError exception.
        """
        assert isInIOThread(), "RequestCache must be used on the reactor's thread"
        assert isinstance(number, (int, long)), type(number)
        assert isinstance(prefix, unicode), type(prefix)

        identifier = self._create_identifier(number, prefix)
        cache = self._identifiers.pop(identifier)
        self.cancel_pending_task(cache)
        return cache

    def _on_timeout(self, cache):
        """
        Called CACHE.timeout_delay seconds after CACHE was added to this RequestCache.

        _on_timeout is called for every Cache, except when it has been popped before the timeout expires.  When called
        _on_timeout will CACHE.on_timeout().
        """

        assert isInIOThread(), "RequestCache must be used on the reactor's thread"
        assert isinstance(cache, NumberCache), type(cache)

        self._logger.debug("timeout on %s", cache)
        cache.on_timeout()

        # the on_timeout call could have already removed the identifier from the cache using pop
        identifier = self._create_identifier(cache.number, cache.prefix)
        if identifier in self._identifiers:
            del self._identifiers[identifier]

        self.cancel_pending_task(cache)

    def _create_identifier(self, number, prefix):
        return u"%s:%d" % (prefix, number)

    def clear(self):
        """
        Clear the cache, canceling all pending tasks.

        """
        assert isInIOThread(), "RequestCache must be used on the reactor's thread"

        self._logger.debug("Clearing %s [%s]", self, len(self._identifiers))
        self.cancel_all_pending_tasks()
        self._identifiers.clear()
