from __future__ import absolute_import

from six.moves import xrange
from twisted.internet import reactor
from twisted.internet.defer import Deferred, succeed
from twisted.internet.task import Clock, deferLater, LoopingCall

from .base import TestBase
from ..taskmanager import CLEANUP_FREQUENCY, TaskManager


class TestTaskManager(TestBase):

    def setUp(self):
        super(TestTaskManager, self).setUp()

        self.dispersy_objects = []
        self.tm = TaskManager()
        self.tm._reactor = Clock()

        self.counter = 0

    def tearDown(self):
        self.tm.shutdown_task_manager()
        return super(TestTaskManager, self).tearDown()

    def test_call_later(self):
        self.tm.register_task("test", reactor.callLater(10, lambda: None))

        self.assertTrue(self.tm.is_pending_task_active("test"))

    def test_call_later_and_cancel(self):
        self.tm.register_task("test", reactor.callLater(10, lambda: None))
        self.tm.cancel_pending_task("test")

        self.assertFalse(self.tm.is_pending_task_active("test"))

    def test_call_later_and_replace(self):
        task1 = self.tm.register_task("test", reactor.callLater(10, lambda: None))
        self.tm.replace_task("test", reactor.callLater(10, lambda: None))

        self.assertTrue(self.tm.is_pending_task_active("test"))
        self.assertFalse(task1.active())

    def test_looping_call(self):
        self.tm.register_task("test", LoopingCall(lambda: None)).start(10, now=True)

        self.assertTrue(self.tm.is_pending_task_active("test"))

    def test_looping_call_and_cancel(self):
        self.tm.register_task("test", LoopingCall(lambda: None)).start(10, now=True)
        self.tm.cancel_pending_task("test")

        self.assertFalse(self.tm.is_pending_task_active("test"))

    def test_delayed_looping_call_requires_interval(self):
        self.assertRaises(ValueError, self.tm.register_task, "test", LoopingCall(lambda: None), delay=1)

    def test_delayed_looping_call_requires_LoopingCall_or_Deferred(self):
        self.assertRaises(ValueError, self.tm.register_task, "test not Deferred nor LoopingCall",
                          self.tm._reactor.callLater(0, lambda: None), delay=1)

    def test_delayed_looping_call_register_and_cancel_pre_delay(self):
        self.assertFalse(self.tm.is_pending_task_active("test"))
        self.tm.register_task("test", LoopingCall(lambda: None), delay=1, interval=1)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        self.tm.cancel_pending_task("test")
        self.assertFalse(self.tm.is_pending_task_active("test"))

    def test_delayed_looping_call_register_wait_and_cancel(self):
        self.assertFalse(self.tm.is_pending_task_active("test"))
        lc = LoopingCall(self.count)
        lc.clock = self.tm._reactor
        self.tm.register_task("test", lc, delay=1, interval=1)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        # After one second, the counter has increased by one and the task is still active.
        self.tm._reactor.advance(1)
        self.assertEquals(1, self.counter)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        # After one more second, the counter should be 2
        self.tm._reactor.advance(1)
        self.assertEquals(2, self.counter)
        # After canceling the task the counter should stop increasing
        self.tm.cancel_pending_task("test")
        self.assertFalse(self.tm.is_pending_task_active("test"))
        self.tm._reactor.advance(10)
        self.assertEquals(2, self.counter)

    def test_delayed_deferred(self):
        self.assertFalse(self.tm.is_pending_task_active("test"))
        d = Deferred()
        d.addCallback(self.set_counter)
        self.tm.register_task("test", d, delay=1, value=42)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        # After one second, the deferred has fired
        self.tm._reactor.advance(1)
        self.assertEquals(42, self.counter)
        self.assertFalse(self.tm.is_pending_task_active("test"))

    def test_raise_on_duplicate_task_name(self):
        self.tm.register_task("test", reactor.callLater(10, lambda: None))
        with self.assertRaises(RuntimeError):
            self.tm.register_task("test", reactor.callLater(10, lambda: None))

    def test_duplicate_anon_task_name(self):
        self.tm.register_anonymous_task("test", deferLater(reactor, 10, lambda: None)).addErrback(lambda _: None)
        self.tm.register_anonymous_task("test", deferLater(reactor, 10, lambda: None)).addErrback(lambda _: None)

        deferred_list = self.tm.wait_for_deferred_tasks()
        self.assertEqual(2, len(deferred_list.resultList))

        self.tm.cancel_all_pending_tasks()

    def test_duplicate_anon_task_deferred(self):
        task = deferLater(reactor, 10, lambda: None)
        self.tm.register_anonymous_task("test", task).addErrback(lambda _: None)
        with self.assertRaises(RuntimeError):
            self.tm.register_anonymous_task("test", task).addErrback(lambda _: None)

        self.tm.cancel_all_pending_tasks()

    def test_shutdown(self):
        """
        Test if the TaskManager does not allow new tasks after shutdown().
        """
        self.tm.shutdown_task_manager()
        self.tm.register_anonymous_task("test", deferLater(reactor, 10, lambda: None)).addErrback(lambda _: None)

        deferred_list = self.tm.wait_for_deferred_tasks()
        self.assertEqual(0, len(deferred_list.resultList))

    def test_cleanup(self):
        """
        Test if the tasks are cleaned up after the cleanup frequency has been met.
        """
        deferred = succeed(None)
        for _ in xrange(CLEANUP_FREQUENCY):
            self.tm.register_anonymous_task("test", deferred)

        deferred_list = self.tm.wait_for_deferred_tasks()
        self.assertEqual(0, len(deferred_list.resultList))

    def test_cleanup_remaining(self):
        """
        Test if tasks which have yet to complete are not cleaned.
        """
        deferred = succeed(None)
        self.tm.register_anonymous_task("test", Deferred()).addErrback(lambda _: None)
        for _ in xrange(CLEANUP_FREQUENCY - 1):
            self.tm.register_anonymous_task("test", deferred)

        deferred_list = self.tm.wait_for_deferred_tasks()
        self.assertEqual(1, len(deferred_list.resultList))

    def count(self):
        self.counter += 1

    def set_counter(self, value):
        self.counter = value
