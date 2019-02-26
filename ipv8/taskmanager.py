from __future__ import absolute_import

import logging
from threading import RLock

from twisted.internet import reactor
from twisted.internet.base import DelayedCall
from twisted.internet.defer import Deferred, DeferredList
from twisted.internet.task import LoopingCall

CLEANUP_FREQUENCY = 100


class TaskManager(object):

    """
    Provides a set of tools to mantain a list of twisted "tasks" (Deferred, LoopingCall, DelayedCall) that are to be
    executed during the lifetime of an arbitrary object, usually getting killed with it.
    """
    _reactor = reactor

    def __init__(self):
        self._pending_tasks = {}
        self._cleanup_counter = CLEANUP_FREQUENCY
        self._task_lock = RLock()
        self._shutdown = False
        self._logger = logging.getLogger(self.__class__.__name__)

    def replace_task(self, name, task):
        """
        Replace named task with the new one, cancelling the old one in the process.
        """
        with self._task_lock:
            self.cancel_pending_task(name)
            return self.register_task(name, task)

    def register_task(self, name, task, delay=None, value=None, interval=None):
        """
        Register a task so it can be canceled at shutdown time or by name.
        """
        with self._task_lock:
            if self._shutdown:
                self._logger.warning("Not adding task %s due to shutdown!", str(task))
                is_active, stopfn = self._get_isactive_stopper(task)
                if is_active and stopfn:
                    stopfn()
                return task

            assert isinstance(task, (Deferred, DelayedCall, LoopingCall)), (task, isinstance(task, Deferred))

            if self.is_pending_task_active(name):
                self.replace_task(name, task)
                raise RuntimeError("Task already exists: '%s'" % name)

            if delay is not None:
                if isinstance(task, Deferred):
                    dc = self._reactor.callLater(delay, task.callback, value)
                elif isinstance(task, LoopingCall):
                    if interval is None:
                        raise ValueError("Expecting interval for delayed LoopingCall")
                    dc = self._reactor.callLater(delay, task.start, interval)
                else:
                    raise ValueError("Expecting Deferred or LoopingCall if task is delayed")

                task = (dc, task)

            self._maybe_clean_task_list()
            self._pending_tasks[name] = task
            return task

    def register_anonymous_task(self, basename, task, delay=None, value=None, interval=None):
        """
        Wrapper for register_task to derive a unique name from the basename.
        """
        return self.register_task(basename + str(id(task)), task, delay, value, interval)

    def cancel_pending_task(self, name):
        """
        Cancels the named task
        """
        with self._task_lock:
            self._maybe_clean_task_list()

            task = self._pending_tasks.get(name, None)
            if not task:
                return

            is_active, stopfn = self._get_isactive_stopper(task)
            if is_active and stopfn:
                stopfn()
                self._pending_tasks.pop(name, None)

    def cancel_all_pending_tasks(self):
        """
        Cancels all the registered tasks.
        This usually should be called when stopping or destroying the object so no tasks are left floating around.
        """
        with self._task_lock:
            assert all([isinstance(task, (Deferred, DelayedCall, LoopingCall, tuple))
                        for task in self._pending_tasks.values()]), self._pending_tasks

            for name in list(self._pending_tasks.keys()):
                self.cancel_pending_task(name)

    def is_pending_task_active(self, name):
        """
        Return a boolean determining if a task is active.
        """
        with self._task_lock:
            task = self._pending_tasks.get(name, None)
            return self._get_isactive_stopper(task)[0] if task else False

    def wait_for_deferred_tasks(self):
        """
        Returns a deferred that will fire when all registered Deferreds are done.
        """
        with self._task_lock:
            self._maybe_clean_task_list()
            return DeferredList(list(self._iter_deferreds()))

    def _iter_deferreds(self):
        with self._task_lock:
            for task in self._pending_tasks.values():
                if isinstance(task, Deferred):
                    yield task

    def _get_isactive_stopper(self, task):
        """
        Return a boolean determining if a task is active and its cancel/stop method if the task is registered.
        """
        with self._task_lock:
            if isinstance(task, Deferred):
                # Have in mind that any deferred in the pending tasks list should have been constructed with a
                # canceller function.
                return not task.called, getattr(task, 'cancel', None)
            elif isinstance(task, DelayedCall):
                return task.active(), task.cancel
            elif isinstance(task, LoopingCall):
                return task.running, task.stop
            elif isinstance(task, tuple):
                if task[0].active():
                    return task[0].active(), task[0].cancel
                else:
                    return self._get_isactive_stopper(task[1])
            else:
                return False, None

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

    def shutdown_task_manager(self):
        """
        Clear the task manager, cancel all pending tasks and disallow new tasks being added.
        """
        with self._task_lock:
            self._shutdown = True
            self.cancel_all_pending_tasks()


__all__ = ["TaskManager"]
