from __future__ import annotations

import logging
import time
import traceback
from asyncio import CancelledError, Future, Task, ensure_future, gather, get_running_loop, iscoroutinefunction, sleep
from contextlib import suppress
from functools import wraps
from threading import RLock
from typing import TYPE_CHECKING, Any, Callable, Coroutine, Hashable, Sequence
from weakref import WeakValueDictionary

from .util import coroutine, succeed

if TYPE_CHECKING:
    from concurrent.futures import ThreadPoolExecutor

MAX_TASK_AGE = 600


async def interval_runner(delay: float, interval: float, task: Callable,
                          *args: Any) -> None:  # noqa: ANN401
    """
    Low-level scheduler for tasks that are supposed to run at a given interval.
    """
    await sleep(delay)
    while True:
        await task(*args)
        await sleep(interval)


async def delay_runner(delay: float, task: Callable, *args: Any) -> None:  # noqa: ANN401
    """
    Low-level scheduler for tasks that are supposed to run after a given interval.
    """
    await sleep(delay)
    await task(*args)


def task(func: Callable) -> Callable:
    """
    Register a TaskManager function as an anonymous task and return the Task
    object so that it can be awaited if needed. Any exceptions will be logged.
    Note that if awaited, exceptions will still need to be handled.
    """
    if not iscoroutinefunction(func):
        msg = "Task decorator should be used with coroutine functions only!"
        raise TypeError(msg)

    @wraps(func)
    def wrapper(self: TaskManager, *args: Any, **kwargs: Any) -> Future:  # noqa: ANN401
        return self.register_anonymous_task(func.__name__,
                                            ensure_future(func(self, *args, **kwargs)),
                                            ignore=(Exception,))
    return wrapper


class TaskManager:
    """
    Provides a set of tools to maintain a list of asyncio Tasks that are to be
    executed during the lifetime of an arbitrary object, usually getting killed with it.
    """

    def __init__(self) -> None:
        """
        Create a new TaskManager and start the introspection loop.
        """
        self._pending_tasks: WeakValueDictionary[Hashable, Future] = WeakValueDictionary()
        self._task_lock = RLock()
        self._shutdown = False
        self._counter = 0
        self._logger = logging.getLogger(self.__class__.__name__)

        self._checker = self.register_task("_check_tasks", self._check_tasks,
                                           interval=MAX_TASK_AGE, delay=MAX_TASK_AGE * 1.5)

    def _check_tasks(self) -> None:
        now = time.time()
        for name, task in self._pending_tasks.items():
            if not task.interval and now - task.start_time > MAX_TASK_AGE:  # type: ignore[attr-defined]
                self._logger.warning('Non-interval task "%s" has been running for %.2f!',
                                     name, now - task.start_time)  # type: ignore[attr-defined]

    def replace_task(self, name: Hashable, *args: Any, **kwargs) -> Future:  # noqa: ANN401
        """
        Replace named task with the new one, cancelling the old one in the process.
        """
        new_task: Future = Future()

        def cancel_cb(_: Any) -> None:  # noqa: ANN401
            try:
                new_task.set_result(self.register_task(name, *args, **kwargs))
            except Exception as e:
                new_task.set_exception(e)

        old_task = self.cancel_pending_task(name)
        old_task.add_done_callback(cancel_cb)
        return new_task

    def register_task(self, name: Hashable, task: Callable | Coroutine | Future,  # noqa: C901
                      *args: Any, delay: float | None = None,  # noqa: ANN401
                      interval: float | None = None, ignore: Sequence[type | BaseException] = ()) -> Future:
        """
        Register a Task/(coroutine)function so it can be canceled at shutdown time or by name.
        """
        if not isinstance(task, Task) and not callable(task) and not isinstance(task, Future):
            msg = "Register_task takes a Task/(coroutine)function/Future as a parameter"
            raise TypeError(msg)
        if (interval or delay) and not callable(task):
            msg = "Cannot run non-callable at an interval or with a delay"
            raise ValueError(msg)
        if not isinstance(ignore, tuple) or not all(issubclass(e, Exception) for e in ignore):
            msg = "Ignore should be a tuple of Exceptions or an empty tuple"
            raise ValueError(msg)

        with self._task_lock:
            if self._shutdown:
                self._logger.warning("Not adding task %s due to shutdown!", str(task))
                if isinstance(task, (Task, Future)) and not task.done():
                    task.cancel()
                # We need to return an awaitable in case the caller awaits the output of register_task.
                return succeed(None)

            if self.is_pending_task_active(name):
                raise RuntimeError("Task already exists: '%s'" % name)

            if callable(task):
                task = task if iscoroutinefunction(task) else coroutine(task)
                if interval:
                    # The default delay for looping calls is the same as the interval
                    delay = interval if delay is None else delay
                    task = ensure_future(interval_runner(delay, interval, task, *args))
                elif delay:
                    task = ensure_future(delay_runner(delay, task, *args))
                else:
                    task = ensure_future(task(*args))
            # Since weak references to list/tuple are not allowed, we're not storing start_time/interval
            # in _pending_tasks. Instead, we add them as attributes to the task.
            task.start_time = time.time()  # type: ignore[attr-defined]
            task.interval = interval  # type: ignore[attr-defined]
            # The set_name function is only available in Python 3.8+
            task_name = f"{self.__class__.__name__}:{name}"
            if hasattr(task, "set_name"):
                task.set_name(task_name)
            else:
                task.name = task_name  # type: ignore[attr-defined]

            assert isinstance(task, (Task, Future))

            def done_cb(future: Future) -> None:
                self._pending_tasks.pop(name, None)
                try:
                    future.result()
                except CancelledError:
                    pass
                except ignore as e:  # type: ignore[misc]
                    self._logger.exception("Task resulted in error: %s\n%s", e, "".join(traceback.format_exc()))

            self._pending_tasks[name] = task
            task.add_done_callback(done_cb)
            return task

    def register_anonymous_task(self, basename: str, task: Callable | Coroutine | Future, *args: Any, **kwargs) -> Future:  # noqa: ANN401
        """
        Wrapper for register_task to derive a unique name from the basename.
        """
        self._counter += 1
        return self.register_task(basename + " " + str(self._counter), task, *args, **kwargs)

    def register_executor_task(self, name: str, func: Callable, *args: Any,  # noqa: ANN401
                               executor: ThreadPoolExecutor | None = None, anon: bool = False, **kwargs) -> Future:
        """
        Run a synchronous function on the Asyncio threadpool. This function does not work with async functions.
        """
        if not callable(func) or iscoroutinefunction(func):
            msg = "Expected a non-async function as a parameter"
            raise TypeError(msg)

        future = get_running_loop().run_in_executor(executor, func, *args, **kwargs)
        if anon:
            return self.register_anonymous_task(name, future)
        return self.register_task(name, future)

    def cancel_pending_task(self, name: Hashable) -> Future:
        """
        Cancels the named task.
        """
        with self._task_lock:
            task = self._pending_tasks.get(name, None)
            if not task:
                return succeed(None)

            if not task.done():
                task.cancel()
                self._pending_tasks.pop(name, None)
            return task

    def cancel_all_pending_tasks(self) -> list[Future]:
        """
        Cancels all the registered tasks.
        This usually should be called when stopping or destroying the object so no tasks are left floating around.
        """
        with self._task_lock:
            assert all(isinstance(t, (Task, Future)) for t in self._pending_tasks.values()), self._pending_tasks
            return [self.cancel_pending_task(name) for name in list(self._pending_tasks.keys())]

    def is_pending_task_active(self, name: Hashable) -> bool:
        """
        Return a boolean determining if a task is active.
        """
        with self._task_lock:
            task = self._pending_tasks.get(name, None)
            return not task.done() if task else False

    def get_task(self, name: Hashable) -> Future | None:
        """
        Return a task if it exists. Otherwise, return None.
        """
        with self._task_lock:
            return self._pending_tasks.get(name, None)

    def get_tasks(self) -> list[Future]:
        """
        Returns a list of all registered tasks, excluding tasks the are created by the TaskManager itself.
        """
        with self._task_lock:
            return [t for t in self._pending_tasks.values() if t != self._checker]

    def get_anonymous_tasks(self, base_name: str) -> list[Future]:
        """
        Return all tasks with a given base name.

        Note that this method will return ALL tasks that start with the given base name, including non-anonymous ones.
        """
        with self._task_lock:
            return [t[1] for t in self._pending_tasks.items() if isinstance(t[0], str) and t[0].startswith(base_name)]

    async def wait_for_tasks(self) -> None:
        """
        Waits until all registered tasks are done.
        """
        tasks = self.get_tasks()
        if tasks:
            await gather(*tasks, return_exceptions=True)

    async def shutdown_task_manager(self) -> None:
        """
        Clear the task manager, cancel all pending tasks and disallow new tasks being added.
        """
        with self._task_lock:
            self._shutdown = True
            tasks = self.cancel_all_pending_tasks()

        if tasks:
            with suppress(CancelledError):
                await gather(*tasks)


__all__ = ["TaskManager", "task"]
