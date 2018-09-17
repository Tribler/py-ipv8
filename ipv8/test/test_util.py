from __future__ import absolute_import

from twisted.internet import reactor
from twisted.internet.defer import fail, inlineCallbacks, returnValue, succeed
from twisted.internet.task import deferLater
from twisted.internet.threads import deferToThread

from .base import TestBase
from ..util import blocking_call_on_reactor_thread


class TestUtil(TestBase):

    @inlineCallbacks
    def test_blocking_call_in_thread(self):
        """
        Check if the reactor thread is properly blocked by a threaded function.
        """
        @blocking_call_on_reactor_thread
        @inlineCallbacks
        def waiter():
            # 'Release' our claim on the reactor thread.
            # blocking_call_on_reactor_thread should prevent anything else being scheduled though.
            yield deferLater(reactor, 0.01, lambda: None)
            waiter.variable += 1
            returnValue(waiter.variable)

        @blocking_call_on_reactor_thread
        def quicker():
            # Immediately use the reactor thread and return
            waiter.variable += 1
            return succeed(waiter.variable)

        waiter.variable = 1

        # 'Release' the reactor thread and increment waiter.variable
        # If release didn't allow other to be scheduled, waiter.variable is now 2
        # If quicker() came first, waiter.variable is now 3 (bad)
        value = yield deferToThread(waiter)
        # Claim reactor thread and increment waiter.variable
        # If waiter() came first, waiter.variable is now 3
        # If quicker() managed to sneak in before this, waiter.variable is now 2 (bad)
        value2 = yield deferToThread(quicker)

        self.assertEqual(value, 2)
        self.assertEqual(value2, 3)

    @inlineCallbacks
    def test_blocking_call_in_thread_with_error(self):
        """
        Check if a blocking call propagates its errors from a thread.
        """
        @blocking_call_on_reactor_thread
        def quicker():
            return fail(RuntimeError())

        success = True
        try:
            yield deferToThread(quicker)
        except RuntimeError:
            success = False

        self.assertFalse(success)
