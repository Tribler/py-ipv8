from asyncio import Future, ensure_future, get_event_loop, sleep
from contextlib import suppress

from .base import TestBase
from ..taskmanager import TaskManager, task
from ..util import coroutine


class TestTaskManager(TestBase):

    def setUp(self):
        super(TestTaskManager, self).setUp()
        self.tm = TaskManager()
        self.counter = 0

    async def tearDown(self):
        await self.tm.shutdown_task_manager()
        return await super(TestTaskManager, self).tearDown()

    def test_call_later(self):
        self.tm.register_task("test", lambda: None, delay=10)
        self.assertTrue(self.tm.is_pending_task_active("test"))

    def test_call_later_and_cancel(self):
        self.tm.register_task("test", lambda: None, delay=10)
        self.tm.cancel_pending_task("test")
        self.assertFalse(self.tm.is_pending_task_active("test"))

    async def test_replace_with_duplicate(self):
        task1 = self.tm.register_task("test", lambda: None, delay=10)
        await self.tm.replace_task("test", lambda: None, delay=10)
        await sleep(.1)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        self.assertTrue(task1.cancelled())

    async def test_replace_without_duplicate(self):
        task = await self.tm.replace_task("test", lambda: None, delay=10)
        await sleep(.1)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        self.assertFalse(task.done())

    async def test_replace_with_error(self):
        with self.assertRaises(ValueError):
            await self.tm.replace_task("test", "bad argument", delay=10)

    def test_looping_call(self):
        self.tm.register_task("test", lambda: None, interval=10)
        self.assertTrue(self.tm.is_pending_task_active("test"))

    def test_looping_call_and_cancel(self):
        self.tm.register_task("test", lambda: None, interval=10)
        self.tm.cancel_pending_task("test")
        self.assertFalse(self.tm.is_pending_task_active("test"))

    def test_delayed_looping_call_requires_coroutine(self):
        with self.assertRaises(TypeError):
            self.tm.register_task("test", ensure_future(coroutine(lambda: None)), delay=1)

    def test_delayed_looping_call_register_and_cancel_pre_delay(self):
        self.assertFalse(self.tm.is_pending_task_active("test"))
        self.tm.register_task("test", lambda: None, delay=1, interval=1)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        self.tm.cancel_pending_task("test")
        self.assertFalse(self.tm.is_pending_task_active("test"))

    async def test_delayed_looping_call_register_wait_and_cancel(self):
        self.assertFalse(self.tm.is_pending_task_active("test"))
        self.tm.register_task("test", self.count, interval=.1)
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

    def test_raise_on_duplicate_task_name(self):
        self.tm.register_task("test", lambda: None)
        with self.assertRaises(RuntimeError):
            self.tm.register_task("test", lambda: None)

    def test_duplicate_anon_task(self):
        task = lambda: None
        self.tm.register_anonymous_task("test", task)
        self.tm.register_anonymous_task("test", task)
        self.assertEqual(2, len(self.tm.get_tasks()))
        self.tm.cancel_all_pending_tasks()

    async def test_shutdown(self):
        """
        Test if the TaskManager does not allow new tasks after shutdown().
        """
        await self.tm.shutdown_task_manager()
        self.tm.register_anonymous_task("test", lambda: None)
        self.assertFalse(self.tm.is_pending_task_active('test'))

    async def test_cleanup(self):
        """
        Test if the tasks are cleaned up after the cleanup frequency has been met.
        """
        await self.tm.register_anonymous_task("test", lambda: None)
        self.assertEqual(0, len(self.tm.get_tasks()))

    async def test_cleanup_remaining(self):
        """
        Test if tasks which have yet to complete are not cleaned.
        """
        await self.tm.register_anonymous_task("test", lambda: None)
        self.tm.register_anonymous_task("test", sleep, 10)
        self.assertEqual(1, len(self.tm.get_tasks()))

    async def test_task_with_exception(self):
        def exception_handler(_, __):
            exception_handler.called = True
        exception_handler.called = False

        get_event_loop().set_exception_handler(exception_handler)
        with suppress(ZeroDivisionError):
            await self.tm.register_task('test', lambda: 1 / 0)
        self.assertTrue(exception_handler.called)

    async def test_task_with_exception_ignore(self):
        def exception_handler(_, __):
            exception_handler.called = True
        exception_handler.called = False

        get_event_loop().set_exception_handler(exception_handler)
        with suppress(ZeroDivisionError):
            await self.tm.register_task('test', lambda: 1 / 0, ignore=(ZeroDivisionError,))
        self.assertFalse(exception_handler.called)

    async def test_task_decorator_coro(self):
        future = Future()

        @task
        async def task_func(_):
            future.set_result(None)
        task_func(self.tm)
        await future

    def test_task_decorator_no_coro(self):
        with self.assertRaises(TypeError):
            @task
            def task_func(_):
                pass

    def count(self):
        self.counter += 1

    def set_counter(self, value):
        self.counter = value
