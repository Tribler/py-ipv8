import logging
from asyncio import CancelledError, Future, Task, ensure_future, gather, iscoroutinefunction, sleep
from contextlib import suppress
from inspect import isgeneratorfunction
from threading import RLock

from .util import succeed

CLEANUP_FREQUENCY = 100


async def interval_runner(delay, interval, task, *args, **kwargs):
    await sleep(delay)
    while True:
        await task(*args, **kwargs)
        await sleep(interval)


async def delay_runner(delay, task, *args, **kwargs):
    await sleep(delay)
    await task(*args, **kwargs)


class TaskManager(object):
    """
    Provides a set of tools to maintain a list of asyncio Tasks that are to be
    executed during the lifetime of an arbitrary object, usually getting killed with it.
    """

    def __init__(self):
        self._pending_tasks = {}
        self._cleanup_counter = CLEANUP_FREQUENCY
        self._task_lock = RLock()
        self._shutdown = False
        self._logger = logging.getLogger(self.__class__.__name__)

    def replace_task(self, name, *args, **kwargs):
        """
        Replace named task with the new one, cancelling the old one in the process.
        """
        new_task = Future()

        def cancel_cb(cancelled_future):
            with suppress(CancelledError):
                cancelled_future.result()
            new_task.set_result(self.register_task(name, *args, **kwargs))

        cancel_future = self.cancel_pending_task(name)
        cancel_future.add_done_callback(cancel_cb)
        return new_task

    def register_task(self, name, task, *args, delay=None, interval=None):
        """
        Register a coroutine/Task so it can be canceled at shutdown time or by name.
        """
        if not isinstance(task, (Task, Future)) and not iscoroutinefunction(task) and not isgeneratorfunction(task):
            raise ValueError('Register_task takes a coroutine/generator function or a Task/Future as a parameter')
        if (interval or delay) and isinstance(task, (Task, Future)):
            raise ValueError('Cannot run Task/Future at an interval or with a delay')

        with self._task_lock:
            if self._shutdown:
                self._logger.warning("Not adding task %s due to shutdown!", str(task))
                if isinstance(task, (Task, Future)):
                    is_active, stopfn = self._get_isactive_stopper(task)
                    if is_active and stopfn:
                        stopfn()
                return task

            if self.is_pending_task_active(name):
                raise RuntimeError("Task already exists: '%s'" % name)

            if iscoroutinefunction(task) or isgeneratorfunction(task):
                if interval:
                    # The default delay for looping calls is the same as the interval
                    delay = interval if delay is None else delay
                    task = ensure_future(interval_runner(delay, interval, task, *args))
                elif delay:
                    task = ensure_future(delay_runner(delay, task, *args))
                else:
                    task = ensure_future(task(*args))

            assert isinstance(task, (Task, Future))

            self._maybe_clean_task_list()
            self._pending_tasks[name] = task
            return task

    def register_anonymous_task(self, basename, task, *args, delay=None, interval=None):
        """
        Wrapper for register_task to derive a unique name from the basename.
        """
        return self.register_task(basename + str(id(task)), task, *args, delay=delay, interval=interval)

    def cancel_pending_task(self, name):
        """
        Cancels the named task
        """
        with self._task_lock:
            self._maybe_clean_task_list()

            task = self._pending_tasks.get(name, None)
            if not task:
                return succeed(None)

            is_active, stopfn = self._get_isactive_stopper(task)
            if is_active and stopfn:
                def done_cb(future):
                    with suppress(CancelledError):
                        future.result()
                task.add_done_callback(done_cb)
                stopfn()
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
            return self._get_isactive_stopper(task)[0] if task else False

    def get_tasks(self):
        """
        Returns a list of all registered tasks.
        """
        with self._task_lock:
            self._maybe_clean_task_list()
            return list(self._iter_tasks())

    async def wait_for_tasks(self):
        """
        Waits until all registered tasks are done.
        """
        with self._task_lock:
            tasks = self.get_tasks()
            if tasks:
                await gather(*tasks)

    def _iter_tasks(self):
        with self._task_lock:
            for task in self._pending_tasks.values():
                yield task

    def _get_isactive_stopper(self, task):
        """
        Return a boolean determining if a task is active and its cancel/stop method if the task is registered.
        """
        with self._task_lock:
            return not task.done(), task.cancel

    def _maybe_clean_task_list(self):
        """
        Removes finished tasks from the task list.
        """
        with self._task_lock:
            if self._cleanup_counter:
                self._cleanup_counter -= 1
            else:
                self._cleanup_counter = CLEANUP_FREQUENCY
                for name in list(self._pending_tasks.keys()):
                    if not self.is_pending_task_active(name):
                        self._pending_tasks.pop(name, None)

    async def shutdown_task_manager(self):
        """
        Clear the task manager, cancel all pending tasks and disallow new tasks being added.
        """
        with self._task_lock:
            self._shutdown = True
            with suppress(CancelledError):
                tasks = self.cancel_all_pending_tasks()
                if tasks:
                    await gather(*tasks)


__all__ = ["TaskManager"]
