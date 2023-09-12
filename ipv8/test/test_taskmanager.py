from __future__ import annotations

from asyncio import AbstractEventLoop, Future, ensure_future, get_running_loop, sleep
from contextlib import suppress
from typing import Any

from ..taskmanager import TaskManager, task
from ..util import coroutine
from .base import TestBase


class TestTaskManager(TestBase):
    """
    Tests related to the task manager.
    """

    def setUp(self) -> None:
        """
        Create a task manager.
        """
        super().setUp()
        self.tm = TaskManager()
        self.counter = 0

    async def tearDown(self) -> None:
        """
        Shut down the task manager.
        """
        await self.tm.shutdown_task_manager()
        return await super().tearDown()

    def test_call_later(self) -> None:
        """
        Check that tasks can be sheduled for the future.
        """
        self.tm.register_task("test", lambda: None, delay=10)
        self.assertTrue(self.tm.is_pending_task_active("test"))

    def test_call_later_and_cancel(self) -> None:
        """
        Check that scheduled tasks can be canceled.
        """
        self.tm.register_task("test", lambda: None, delay=10)
        self.tm.cancel_pending_task("test")
        self.assertFalse(self.tm.is_pending_task_active("test"))

    async def test_replace_with_duplicate(self) -> None:
        """
        Check that a scheduled task can be overwritten by name, cancelling the previous task.
        """
        task1 = self.tm.register_task("test", lambda: None, delay=10)
        await self.tm.replace_task("test", lambda: None, delay=10)
        await sleep(.1)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        self.assertTrue(task1.cancelled())

    async def test_replace_without_duplicate(self) -> None:
        """
        Check that replacing without a running task with the same name simply registers the task.
        """
        task = await self.tm.replace_task("test", lambda: None, delay=10)
        await sleep(.1)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        self.assertFalse(task.done())

    async def test_replace_with_error(self) -> None:
        """
        Check that a task with faulty arguments raises a ValueError when replaced.
        """
        with self.assertRaises(ValueError):
            await self.tm.replace_task("test", "bad argument", delay=10)

    def test_looping_call(self) -> None:
        """
        Check that repeating calls can be registered.
        """
        self.tm.register_task("test", lambda: None, interval=10)
        self.assertTrue(self.tm.is_pending_task_active("test"))

    def test_looping_call_and_cancel(self) -> None:
        """
        Check that repeating calls can be cancelled.
        """
        self.tm.register_task("test", lambda: None, interval=10)
        self.tm.cancel_pending_task("test")
        self.assertFalse(self.tm.is_pending_task_active("test"))

    def test_delayed_looping_call_requires_coroutine(self) -> None:
        """
        Check that delayed calls cannot be futures.
        """
        with self.assertRaises(TypeError):
            self.tm.register_task("test", ensure_future(coroutine(lambda: None)), delay=1)

    def test_delayed_looping_call_register_and_cancel_pre_delay(self) -> None:
        """
        Check that a delayed repeating call can be cancelled.
        """
        self.assertFalse(self.tm.is_pending_task_active("test"))
        self.tm.register_task("test", lambda: None, delay=1, interval=1)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        self.tm.cancel_pending_task("test")
        self.assertFalse(self.tm.is_pending_task_active("test"))

    async def test_delayed_looping_call_register_wait_and_cancel(self) -> None:
        """
        Check if interval tasks are actually properly called.
        """
        self.assertFalse(self.tm.is_pending_task_active("test"))
        task1 = self.tm.register_task("test", self.count, interval=.1)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        await sleep(.15)
        self.assertEqual(1, self.counter)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        await sleep(.1)
        self.assertEqual(2, self.counter)
        # After canceling the task the counter should stop increasing
        task2 = self.tm.cancel_pending_task("test")
        self.assertFalse(self.tm.is_pending_task_active("test"))
        await sleep(.1)
        self.assertEqual(2, self.counter)
        self.assertTrue(task1.cancelled())
        self.assertTrue(task2.cancelled())

    def test_raise_on_duplicate_task_name(self) -> None:
        """
        Check that a normal register task cannot be used as a replace task.
        """
        self.tm.register_task("test", lambda: None)
        with self.assertRaises(RuntimeError):
            self.tm.register_task("test", lambda: None)

    def test_duplicate_anon_task(self) -> None:
        """
        Tests that anonymous tasks allow the same base name to be reused.
        """
        task = lambda: None
        self.tm.register_anonymous_task("test", task)
        self.tm.register_anonymous_task("test", task)
        self.assertEqual(2, len(self.tm.get_tasks()))
        self.tm.cancel_all_pending_tasks()

    async def test_shutdown(self) -> None:
        """
        Check if the TaskManager does not allow new tasks after shutdown().
        """
        await self.tm.shutdown_task_manager()
        task = self.tm.register_anonymous_task("test", lambda: None)
        self.assertFalse(self.tm.is_pending_task_active('test'))
        self.assertFalse(task.cancelled())

    async def test_cleanup(self) -> None:
        """
        Check if the tasks are cleaned up after the cleanup frequency has been met.
        """
        await self.tm.register_anonymous_task("test", lambda: None)
        self.assertEqual(0, len(self.tm.get_tasks()))

    async def test_cleanup_remaining(self) -> None:
        """
        Check if tasks which have yet to complete are not cleaned.
        """
        await self.tm.register_anonymous_task("test", lambda: None)
        task = self.tm.register_anonymous_task("test", sleep, 10)
        self.assertEqual(1, len(self.tm.get_tasks()))
        self.assertFalse(task.cancelled())

    async def test_task_with_exception(self) -> None:
        """
        Check if tasks forward their exceptions properly.
        """
        def exception_handler(_: AbstractEventLoop, __: dict[str, Any]) -> None:
            exception_handler.called = True
        exception_handler.called = False

        get_running_loop().set_exception_handler(exception_handler)
        with suppress(ZeroDivisionError):
            await self.tm.register_task('test', lambda: 1 / 0)
        self.assertTrue(exception_handler.called)

    async def test_task_with_exception_ignore(self) -> None:
        """
        Check that ignored exceptions do not end up in the main/generic exception handler.

        Note that they are still locally raised!
        """
        def exception_handler(_: AbstractEventLoop, __: dict[str, Any]) -> None:
            exception_handler.called = True
        exception_handler.called = False

        get_running_loop().set_exception_handler(exception_handler)
        with suppress(ZeroDivisionError):
            await self.tm.register_task('test', lambda: 1 / 0, ignore=(ZeroDivisionError,))
        self.assertFalse(exception_handler.called)

    async def test_task_decorator_coro(self) -> None:
        """
        Check that the task decorator allows functions to be wrapped.
        """
        future = Future()

        @task
        async def task_func(_: TaskManager) -> None:
            future.set_result(None)
        task_func(self.tm)
        await future

    def test_task_decorator_no_coro(self) -> None:
        """
        Check if an attempt to taskify a non-async function raises a TypeError.
        """
        with self.assertRaises(TypeError):
            @task
            def task_func(_: TaskManager) -> None:
                pass

    def count(self) -> None:
        """
        A function used to increment the local counter.
        """
        self.counter += 1

    def set_counter(self, value: int) -> None:
        """
        Set the testing counter to a fixed value.
        """
        self.counter = value
