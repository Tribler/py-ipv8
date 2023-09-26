Task Management
===============

This document assumes you have a basic understanding of network overlays in IPv8, as documented in `the overlay tutorial <../basics/overlay_tutorial.html>`_.
You will learn how to use the IPv8's ``TaskManager`` class to manage ``asyncio`` tasks and how to use ``NumberCache`` to manage ``Future`` instances.

What is a task?
---------------

Essentially, a task is a way for ``asyncio`` to point to code that should be executed at some point.
The ``asyncio`` library checks if it has something to execute and executes it until it has no more tasks to execute.
However, there are many intricacies when dealing with tasks.
Consider the following example:

.. literalinclude:: tasks_tutorial_1.py

Can you guess what will be printed?

The correct answer is ``[2, 3, 5, 4]`` and equally important is that the answer changes to ``[2, 3, 5]`` if you omit the final ``await asyncio.sleep(1)``.
Feel free to skip to the "The TaskManager" section if both of these answers are obvious to you.

Let's run through ``execute_me()`` to explain this behavior:

1. The ``execute_me_too(1)`` will not be executed, though your application will not crash. You will be informed of this through the ``RuntimeWarning: coroutine 'execute_me_too' was never awaited`` warning message. You should have awaited this ``execute_me_too`` call, we do this properly in the next line.
2. By awaiting ``execute_me_too(2)`` the ``execute_me()`` call will wait until ``execute_me_too(2)`` has finished executing. This adds the value ``2`` to the ``COMPLETED`` list.
3. After waiting for ``execute_me_too(2)`` to finish ``COMPLETED.append(3)`` is allowed to append the value ``3`` to the ``COMPLETED`` list.
4. By creating a future for ``execute_me_too(4)``, we allow ``execute_me()`` to continue executing.
5. While we wait for ``execute_me_too(4)`` to finish, ``COMPLETED.append(5)`` can already access the ``COMPLETED`` list and insert its value ``5``.
6. While ``execute_me()`` waits for another second, ``execute_me_too(4)`` is allowed to add to the ``COMPLETED`` list.

Note that if you had omitted ``await asyncio.sleep(1)``, the ``execute_me()`` call would not be waiting for anything anymore and return (outputting ``[2, 3, 5]``).
Instead, the future returned by ``asyncio.ensure_future()`` should have been awaited, as follows:

.. literalinclude:: tasks_tutorial_2.py
   :lines: 11-16

As an added bonus, this is also faster than the previous method.
This new example will finish when the ``execute_me_too(4)`` call completes, instead of after waiting a full second.

This concludes the basics of ``asyncio`` tasks.
Now, we'll show you how to make your life easier by using IPv8's ``TaskManager`` class.

The TaskManager
---------------

Managing ``Future`` instances and ``coroutine`` instances is complex and error-prone and, to help you with managing these, IPv8 has the ``TaskManager`` class.
The ``TaskManager`` takes care of managing all of your calls that have not completed yet and allows you to cancel them on demand.
You can even find this class in a separate PyPi repository: https://pypi.org/project/ipv8-taskmanager/

Adding tasks
^^^^^^^^^^^^

To add tasks to your ``TaskManager`` you can call ``register_task()``.
You register a task with a name, which you can later use to inspect the state of a task or cancel it.
For example:

.. literalinclude:: tasks_tutorial_3.py

This example prints ``[2]``.
If you had not called ``wait_for_tasks()`` before ``shutdown_task_manager()`` in this example, all of your registered tasks would have been canceled, printing ``[]``.

In some cases you may also not be interested in canceling a particular task.
For this use case the ``register_anonymous_task()`` call exists, for example:

.. literalinclude:: tasks_tutorial_4.py
   :lines: 16-19

Note that this example takes just over half a second to execute, all 20 calls to ``execute_me_too()`` are scheduled at (almost) the same time!

Periodic and delayed tasks
^^^^^^^^^^^^^^^^^^^^^^^^^^

Next to simply adding tasks, the ``TaskManager`` also allows you to invoke calls after a delay or periodically.
The following example will add the value ``1`` to the ``COMPLETED`` list periodically and inject a single value of ``2`` after half a second:

.. literalinclude:: tasks_tutorial_5.py
   :lines: 8-25

This example prints ``[1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]``.

Note that you can also create a task with both an interval and a delay.

Community Integration
^^^^^^^^^^^^^^^^^^^^^

For your convenience, every ``Community`` is also a ``TaskManager``.
However, try to avoid spawning any tasks in the ``__init__`` of your ``Community``.
Specifically, you could end up scheduling a task in between your ``Community`` and other ``Community`` initialization.
Working with a half-initialized IPv8 may lead to problems.
This practice also makes your ``Community`` more difficult to test.

If you do end up in a situation where you absolutely must schedule a task from the ``__init__()``, you can use the ``TaskManager``'s ``cancel_all_pending_tasks()`` method to cancel all registered tasks.
This is an example of how to deal with this in your unit tests:

.. literalinclude:: tasks_tutorial_6.py
   :lines: 20-28

Futures and caches
^^^^^^^^^^^^^^^^^^

Sometimes you may find that certain tasks belong to a message context.
In other words, you may have a task that belongs to a *cache* (see `the storing states tutorial <../basics/overlay_tutorial.html>`_).
By registering a ``Future`` instance in your ``NumberCache`` subclass it will automatically be canceled when the ``NumberCache`` gets canceled or times out.
You can do so using the ``register_future()`` method.
This is a complete example:

.. literalinclude:: tasks_tutorial_7.py

This example prints:

 .. code-block:: console

   future0.result()=True
   future1.result()=False
   future2.cancelled()=True

This example showcases the three states your ``Future`` may find itself in.
First, it may have been called and received an explicit result (``True`` in this case).
Second, the future may have timed out.
By default a timed-out ``Future`` will have its result set to ``None``, but you can even give this method an exception class to have it raise an exception for you.
In this example we set the value to ``False``.
Third and last is the case where your future was cancelled, which will raise a ``asyncio.exceptions.CancelledError`` if you ``await`` it.
