import logging
import time
import traceback
from asyncio import CancelledError, Future, Task, ensure_future, gather, iscoroutinefunction, sleep
from contextlib import suppress
from functools import wraps
from threading import RLock
from weakref import WeakValueDictionary

from .util import coroutine, succeed

MAX_TASK_AGE = 600


async def interval_runner(delay, interval, task, *args):
    await sleep(delay)
    while True:
        await task(*args)
        await sleep(interval)


async def delay_runner(delay, task, *args):
    await sleep(delay)
    await task(*args)


def task(func):
    """
    Register a TaskManager function as an anonymous task and return the Task
    object so that it can be awaited if needed. Any exceptions will be logged.
    Note that if awaited, exceptions will still need to be handled.
    """
    if not iscoroutinefunction(func):
        raise TypeError('Task decorator should be used with coroutine functions only!')

    @wraps(func)
    def wrapper(self, *args, **kwargs):
        return self.register_anonymous_task(func.__name__,
                                            ensure_future(func(self, *args, **kwargs)),
                                            ignore=(Exception,))
    return wrapper


class TaskManager(object):
    """
    Provides a set of tools to maintain a list of asyncio Tasks that are to be
    executed during the lifetime of an arbitrary object, usually getting killed with it.
    """

    def __init__(self):
        self._pending_tasks = WeakValueDictionary()
        self._task_lock = RLock()
        self._shutdown = False
        self._counter = 0
        self._logger = logging.getLogger(self.__class__.__name__)

        self._checker = self.register_task('_check_tasks', self._check_tasks,
                                           interval=MAX_TASK_AGE, delay=MAX_TASK_AGE * 1.5)

    def _check_tasks(self):
        now = time.time()
        for name, task in self._pending_tasks.items():
            if not task.interval and now - task.start_time > MAX_TASK_AGE:
                self._logger.warning('Non-interval task "%s" has been running for %.2f!', name, now - task.start_time)

    def replace_task(self, name, *args, **kwargs):
        """
        Replace named task with the new one, cancelling the old one in the process.
        """
        new_task = Future()

        def cancel_cb(_):
            try:
                new_task.set_result(self.register_task(name, *args, **kwargs))
            except Exception as e:
                new_task.set_exception(e)

        old_task = self.cancel_pending_task(name)
        old_task.add_done_callback(cancel_cb)
        return new_task

    def register_task(self, name, task, *args, delay=None, interval=None, ignore=()):
        """
        Register a Task/(coroutine)function so it can be canceled at shutdown time or by name.
        """
        if not isinstance(task, Task) and not iscoroutinefunction(task) and not callable(task):
            raise ValueError('Register_task takes a Task or a (coroutine)function as a parameter')
        if (interval or delay) and isinstance(task, Task):
            raise ValueError('Cannot run Task at an interval or with a delay')
        if not isinstance(ignore, tuple) or not all((issubclass(e, Exception) for e in ignore)):
            raise ValueError('Ignore should be a tuple of Exceptions or None')

        with self._task_lock:
            if self._shutdown:
                self._logger.warning("Not adding task %s due to shutdown!", str(task))
                if isinstance(task, (Task, Future)):
                    if not task.done():
                        task.cancel()
                # We need to return an awaitable in case the caller awaits the output of register_task.
                return succeed(None)

            if self.is_pending_task_active(name):
                raise RuntimeError("Task already exists: '%s'" % name)

            if iscoroutinefunction(task) or callable(task):
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
            # in _pending_tasks. Instead we add them as attributes to the task.
            task.start_time = time.time()
            task.interval = interval
            # The set_name function is only available in Python 3.8+
            task_name = f'{self.__class__.__name__}:{name}'
            if hasattr(task, 'set_name'):
                task.set_name(task_name)
            else:
                task.name = task_name

            assert isinstance(task, Task)

            def done_cb(future):
                self._pending_tasks.pop(name, None)
                try:
                    future.result()
                except CancelledError:
                    pass
                except ignore as e:
                    self._logger.error('Task resulted in error: %s\n%s', e, ''.join(traceback.format_exc()))

            self._pending_tasks[name] = task
            task.add_done_callback(done_cb)
            return task

    def register_anonymous_task(self, basename, task, *args, **kwargs):
        """
        Wrapper for register_task to derive a unique name from the basename.
        """
        self._counter += 1
        return self.register_task(basename + ' ' + str(self._counter), task, *args, **kwargs)

    def cancel_pending_task(self, name):
        """
        Cancels the named task
        """
        with self._task_lock:
            task = self._pending_tasks.get(name, None)
            if not task:
                return succeed(None)

            if not task.done():
                task.cancel()
                self._pending_tasks.pop(name, None)
            return task

    def cancel_all_pending_tasks(self):
        """
        Cancels all the registered tasks.
        This usually should be called when stopping or destroying the object so no tasks are left floating around.
        """
        with self._task_lock:
            assert all([isinstance(t, (Task, Future)) for t in self._pending_tasks.values()]), self._pending_tasks
            return [self.cancel_pending_task(name) for name in list(self._pending_tasks.keys())]

    def is_pending_task_active(self, name):
        """
        Return a boolean determining if a task is active.
        """
        with self._task_lock:
            task = self._pending_tasks.get(name, None)
            return not task.done() if task else False

    def get_tasks(self):
        """
        Returns a list of all registered tasks, excluding tasks the are created by the TaskManager itself.
        """
        with self._task_lock:
            return [t for t in self._pending_tasks.values() if t != self._checker]

    async def wait_for_tasks(self):
        """
        Waits until all registered tasks are done.
        """
        tasks = self.get_tasks()
        if tasks:
            await gather(*tasks, return_exceptions=True)

    async def shutdown_task_manager(self):
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
