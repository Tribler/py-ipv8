Community Best Practices
========================

When working with a small ``Community`` class you can get away with putting all of your code into the same file.
However, as your codebase grows this simple approach becomes unmaintainable (most importantly it becomes hard to test).
More formally, whereas you should always start with the KISS principle (**keep it simple, stupid**) we'll show how you can organize your ``Community`` as it grows larger (using the SOLID design principles).

**Pledge:** *One of the founding principles of IPv8 is to allow you to program in any style you like. IPv8 should never force your code to fit any particular architecture. This is what separates IPv8 from its predecessor Dispersy.*

SOLID by example
----------------

The first letter of the SOLID principles stands for the single-responsibility principle.
We'll now discuss what this means for your ``Community``.

Any ``Community`` is in charge of sending and receiving messages between ``Peer`` instances (identities managed by the ``Network`` class).
A direct implication of this is that any code in your ``Community`` which is not concerned with handling or sending messages should be extracted.
This may be hard to spot, so let's discuss a practical example:

 .. code-block:: python

    class MyCommunity(Community):

        def __init__(self, settings: CommunitySettings):
            super().__init__(settings)
            # ... details omitted ...
            self.last_value = 0
            self.total_value = 0

        @lazy_wrapper(MyPayload)
        def on_my_payload(self, peer, payload):
            self.last_value = payload.value
            self.total_value += payload.value
            self.ez_send(peer, MyResponsePayload(self.total_value))

Is there anything wrong with this code?
No, and you should always strive to keep your code as simple as possible.
However, this style may become unmanageable if your ``Community`` becomes too big.
In this particular example, we see that the ``MyCommunity`` is storing a state of incoming ``payload.value``, which is not its responsibility.
This example doesn't follow the SOLID principles and next we'll apply other principles of SOLID to fix it.

Our previous example completely captures and manages the state of ``payload.value``.
This makes ``MyCommunity`` a god-class, arguably the worst software engineering anti-pattern.
Let's incrementally improve our example.
First we'll delegate the incoming information to a specific interface (the I of *interface segregation* in SOLID).
The following turns ``MyCommunity`` into a mediator:

 .. code-block:: python

    class MyCommunity(Community):

        def __init__(self, settings: CommunitySettings):
            super().__init__(settings)
            # ... details omitted ...
            self.value_manager = ValueManager()

        @lazy_wrapper(MyPayload)
        def on_my_payload(self, peer, payload):
            self.value_manager.set_last_value(payload.value)
            self.value_manager.add_to_total(payload.value)
            return_value = self.value_manager.total_value
            self.ez_send(peer, MyResponsePayload(return_value))

Has this improved our code? Yes.
We can now test all of the methods in ``ValueManager`` without having to send messages through the ``MyCommunity``.
Especially if your message handlers are very complex, this can save you a lot of time.
This also improves the readability of your code: the ``ValueManager`` clearly takes care of all value-related state updates.
As the responsibility of value-related updates now lies with the ``ValueManager``, our ``MyCommunity`` now again has a single responsibility.

Is our previous improvement perfect? No.
We have upgraded our ``MyCommunity`` from a god-class pattern to a mediator pattern.
Our class is still performing low-level operations on the ``ValueManager``, violating the dependency inversion principle (the D in SOLID).
Dependency inversion consists of both keeping low-level details of dependencies out of a higher-level class and making generic interfaces.
You can see that the ``MyCommunity`` has to call ``set_last_value`` and ``add_to_total``, which are low-level operations.
Let's fix that:

 .. code-block:: python

    class MyCommunity(Community):

        def __init__(self, settings: CommunitySettings):
            super().__init__(settings)
            # ... details omitted ...
            self.value_manager = ValueManager()

        @lazy_wrapper(MyPayload)
        def on_my_payload(self, peer, payload):
            return_value = self.value_manager.process(payload.value)
            self.ez_send(peer, MyResponsePayload(return_value))

Finally perfection.
Our ``MyCommunity`` no longer has any knowledge of how a ``payload.value`` is processed.
Our ``ValueManager`` can internally process a value, without knowing about the ``payload``.
The return value of ``ValueManager`` is then given back to the ``MyCommunity`` to send a new message, which is its responsibility.
We can still test our ``ValueManager`` independently, but now also provide our ``MyCommunity`` with a mocked ``ValueManager`` to more easily test it.

Some final notes:

- Don't forget that you have ``asyncio`` at your disposal! You can, for example, give your managers an ``asyncio.Future`` for you to await.

- You should be wary when applying the Inversion of Control principle to allow your managers to directly send messages from your ``Community``. This may violate the dependency inversion principle through your inverted control.

``Community`` initialization
----------------------------

To run IPv8 as a service (using ``ipv8_service.py``), you need to be able to launch your overlay from user settings (i.e., a configuration dictionary of strings and ints).
This conflicts with a dependency injection pattern.
A compromise, which is a recurring successful pattern in IPv8, is "create from configuration if not explicitly supplied".
In other words, check if a dependency is given to our constructor and create it from the supplied settings if it is not.
This is an example:

 .. code-block:: python

    class MyCommunitySettings(CommunitySettings):
        value_manager: ValueManager | None = None

    class MyCommunity(Community):
        settings_class = MyCommunitySettings

        def __init__(self, settings: MyCommunitySettings) -> None:
            super().__init__(settings)
            # Create-if-Missing Pattern
            self.value_manager = settings.value_manager or ValueManager()

Note that to pass settings to your overlay it is often better to supply a settings object instead of passing every configuration parameter separately (the latter is known as a *Data Clump* code smell).
Passing your settings as an object avoids passing too many arguments to your ``Community`` (Pylint R0913).
