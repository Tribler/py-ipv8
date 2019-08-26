from __future__ import absolute_import

from asyncio import coroutine, sleep, Future

from six.moves import xrange

from Tribler.Core.Utilities.utilities import succeed
from .base import TestBase
from ..taskmanager import CLEANUP_FREQUENCY, TaskManager


class TestTaskManager(TestBase):

    def setUp(self):
        super(TestTaskManager, self).setUp()
        self.tm = TaskManager()
        self.counter = 0

    async def tearDown(self):
        await self.tm.shutdown_task_manager()
        return await super(TestTaskManager, self).tearDown()

    def test_call_later(self):
        self.tm.register_task("test", coroutine(lambda: None), delay=10)

        self.assertTrue(self.tm.is_pending_task_active("test"))

    def test_call_later_and_cancel(self):
        self.tm.register_task("test", coroutine(lambda: None), delay=10)
        self.tm.cancel_pending_task("test")

        self.assertFalse(self.tm.is_pending_task_active("test"))

    async def test_replace_with_duplicate(self):
        task1 = self.tm.register_task("test", coroutine(lambda: None), delay=10)
        task2 = await self.tm.replace_task("test", coroutine(lambda: None), delay=10)
        await sleep(.1)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        self.assertTrue(task1.cancelled())

    async def test_replace_without_duplicate(self):
        task = await self.tm.replace_task("test", coroutine(lambda: None), delay=10)
        await sleep(.1)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        self.assertFalse(task.done())

    def test_looping_call(self):
        self.tm.register_task("test", coroutine(lambda: None), interval=10)
        self.assertTrue(self.tm.is_pending_task_active("test"))

    def test_looping_call_and_cancel(self):
        self.tm.register_task("test", coroutine(lambda: None), interval=10)
        self.tm.cancel_pending_task("test")
        self.assertFalse(self.tm.is_pending_task_active("test"))

    def test_delayed_looping_call_requires_coroutine(self):
        with self.assertRaises(ValueError):
            self.tm.register_task("test", Future(), delay=1)

    def test_delayed_looping_call_register_and_cancel_pre_delay(self):
        self.assertFalse(self.tm.is_pending_task_active("test"))
        self.tm.register_task("test", coroutine(lambda: None), delay=1, interval=1)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        self.tm.cancel_pending_task("test")
        self.assertFalse(self.tm.is_pending_task_active("test"))

    async def test_delayed_looping_call_register_wait_and_cancel(self):
        # TODO:
        self.assertFalse(self.tm.is_pending_task_active("test"))
        self.tm.register_task("test", coroutine(self.count), interval=.1)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        await sleep(.15)
        self.assertEqual(1, self.counter)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        await sleep(.1)
        self.assertEqual(2, self.counter)
        # After canceling the task the counter should stop increasing
        self.tm.cancel_pending_task("test")
        self.assertFalse(self.tm.is_pending_task_active("test"))
        await sleep(.1)
        self.assertEqual(2, self.counter)

    async def test_delayed_deferred(self):
        self.assertFalse(self.tm.is_pending_task_active("test"))
        future = Future()
        future.add_done_callback(lambda f: self.set_counter(f.result()))
        self.tm.register_task("test", future)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        future.set_result(42)
        await sleep(.1)
        self.assertEqual(42, self.counter)
        self.assertFalse(self.tm.is_pending_task_active("test"))

    def test_raise_on_duplicate_task_name(self):
        self.tm.register_task("test", coroutine(lambda: None))
        with self.assertRaises(RuntimeError):
            self.tm.register_task("test", coroutine(lambda: None))

    async def test_duplicate_anon_task_name(self):
        self.tm.register_anonymous_task("test", Future())
        self.tm.register_anonymous_task("test", Future())
        self.assertEqual(2, len(self.tm.get_tasks()))
        self.tm.cancel_all_pending_tasks()

    def test_duplicate_anon_task_deferred(self):
        task = coroutine(lambda: None)
        self.tm.register_anonymous_task("test", task)
        with self.assertRaises(RuntimeError):
            self.tm.register_anonymous_task("test", task)
        self.tm.cancel_all_pending_tasks()

    async def test_shutdown(self):
        """
        Test if the TaskManager does not allow new tasks after shutdown().
        """
        await self.tm.shutdown_task_manager()
        self.tm.register_anonymous_task("test", coroutine(lambda: None))
        self.assertFalse(self.tm.is_pending_task_active('test'))

    def test_cleanup(self):
        """
        Test if the tasks are cleaned up after the cleanup frequency has been met.
        """
        future = succeed(None)
        for _ in xrange(CLEANUP_FREQUENCY):
            self.tm.register_anonymous_task("test", future)
        self.assertEqual(0, len(self.tm.get_tasks()))

    def test_cleanup_remaining(self):
        """
        Test if tasks which have yet to complete are not cleaned.
        """
        future = succeed(None)
        self.tm.register_anonymous_task("test", Future())
        for _ in xrange(CLEANUP_FREQUENCY - 1):
            self.tm.register_anonymous_task("test", future)
        self.assertEqual(1, len(self.tm.get_tasks()))

    def count(self):
        self.counter += 1

    def set_counter(self, value):
        self.counter = value
