from __future__ import absolute_import

from twisted.internet import reactor
from twisted.internet.defer import Deferred, succeed, inlineCallbacks
from twisted.internet.task import Clock, deferLater, LoopingCall

from ..taskmanager import TaskManager
from .base import TestBase


def untwisted_wrapper(f):
    """
    We need the reactor for this test.
    But, we don't use it ourselves.
    """
    def wrapper(*args, **kwargs):
        f(*args, **kwargs)
        yield succeed(True)
    wrapper.__name__ = f.__name__
    return wrapper


class TestTaskManager(TestBase):

    def setUp(self):
        super(TestTaskManager, self).setUp()

        self.dispersy_objects = []
        self.tm = TaskManager(Clock())

        self.counter = 0

    def tearDown(self):
        self.tm.shutdown_task_manager()
        super(TestTaskManager, self).tearDown()

    @inlineCallbacks
    @untwisted_wrapper
    def test_call_later(self):
        self.tm.register_task("test", reactor.callLater(10, lambda: None))

        self.assertTrue(self.tm.is_pending_task_active("test"))

    @inlineCallbacks
    @untwisted_wrapper
    def test_call_later_and_cancel(self):
        self.tm.register_task("test", reactor.callLater(10, lambda: None))
        self.tm.cancel_pending_task("test")

        self.assertFalse(self.tm.is_pending_task_active("test"))

    @inlineCallbacks
    @untwisted_wrapper
    def test_call_later_and_replace(self):
        task1 = self.tm.register_task("test", reactor.callLater(10, lambda: None))
        self.tm.replace_task("test", reactor.callLater(10, lambda: None))

        self.assertTrue(self.tm.is_pending_task_active("test"))
        self.assertFalse(task1.active())

    @inlineCallbacks
    @untwisted_wrapper
    def test_looping_call(self):
        self.tm.register_task("test", LoopingCall(lambda: None)).start(10, now=True)

        self.assertTrue(self.tm.is_pending_task_active("test"))

    @inlineCallbacks
    @untwisted_wrapper
    def test_looping_call_and_cancel(self):
        self.tm.register_task("test", LoopingCall(lambda: None)).start(10, now=True)
        self.tm.cancel_pending_task("test")

        self.assertFalse(self.tm.is_pending_task_active("test"))

    @inlineCallbacks
    @untwisted_wrapper
    def test_delayed_looping_call_requires_interval(self):
        self.assertRaises(ValueError, self.tm.register_task, "test", LoopingCall(lambda: None), delay=1)

    @inlineCallbacks
    @untwisted_wrapper
    def test_delayed_deferred_requires_value(self):
        self.assertRaises(ValueError, self.tm.register_task, "test", deferLater(reactor, 0.0, lambda: None), delay=1)

    @inlineCallbacks
    @untwisted_wrapper
    def test_delayed_looping_call_requires_LoopingCall_or_Deferred(self):
        self.assertRaises(ValueError, self.tm.register_task, "test not Deferred nor LoopingCall",
                          self.tm.clock.callLater(0, lambda: None), delay=1)

    @inlineCallbacks
    @untwisted_wrapper
    def test_delayed_looping_call_register_and_cancel_pre_delay(self):
        self.assertFalse(self.tm.is_pending_task_active("test"))
        self.tm.register_task("test", LoopingCall(lambda: None), delay=1, interval=1)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        self.tm.cancel_pending_task("test")
        self.assertFalse(self.tm.is_pending_task_active("test"))

    @inlineCallbacks
    @untwisted_wrapper
    def test_delayed_looping_call_register_wait_and_cancel(self):
        self.assertFalse(self.tm.is_pending_task_active("test"))
        lc = LoopingCall(self.count)
        lc.clock = self.tm.clock
        self.tm.register_task("test", lc, delay=1, interval=1)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        # After one second, the counter has increased by one and the task is still active.
        self.tm.clock.advance(1)
        self.assertEquals(1, self.counter)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        # After one more second, the counter should be 2
        self.tm.clock.advance(1)
        self.assertEquals(2, self.counter)
        # After canceling the task the counter should stop increasing
        self.tm.cancel_pending_task("test")
        self.assertFalse(self.tm.is_pending_task_active("test"))
        self.tm.clock.advance(10)
        self.assertEquals(2, self.counter)

    @inlineCallbacks
    @untwisted_wrapper
    def test_delayed_deferred(self):
        self.assertFalse(self.tm.is_pending_task_active("test"))
        d = Deferred()
        d.addCallback(self.set_counter)
        self.tm.register_task("test", d, delay=1, value=42)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        # After one second, the deferred has fired
        self.tm.clock.advance(1)
        self.assertEquals(42, self.counter)
        self.assertFalse(self.tm.is_pending_task_active("test"))

    @inlineCallbacks
    @untwisted_wrapper
    def test_raise_on_duplicate_task_name(self):
        self.tm.register_task("test", reactor.callLater(10, lambda: None))
        with self.assertRaises(RuntimeError):
            self.tm.register_task("test", reactor.callLater(10, lambda: None))

    @inlineCallbacks
    @untwisted_wrapper
    def test_duplicate_anon_task_name(self):
        self.tm.register_anonymous_task("test", deferLater(reactor, 10, lambda: None)).addErrback(lambda _: None)
        self.tm.register_anonymous_task("test", deferLater(reactor, 10, lambda: None)).addErrback(lambda _: None)

        deferred_list = self.tm.wait_for_deferred_tasks()
        self.assertEqual(2, len(deferred_list.resultList))

        self.tm.cancel_all_pending_tasks()

    @inlineCallbacks
    @untwisted_wrapper
    def test_duplicate_anon_task_deferred(self):
        task = deferLater(reactor, 10, lambda: None)
        self.tm.register_anonymous_task("test", task).addErrback(lambda _: None)
        with self.assertRaises(RuntimeError):
            self.tm.register_anonymous_task("test", task).addErrback(lambda _: None)

        self.tm.cancel_all_pending_tasks()

    def count(self):
        self.counter += 1

    def set_counter(self, value):
        self.counter = value
