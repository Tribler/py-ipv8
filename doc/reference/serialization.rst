Message serialization
=====================

IPv8 gives you as much control as possible over the messages you send over the Internet.
The ``Overlay`` (or ``Community``) class lets you send arbitrary strings over the (UDP) ``endpoint``.
However efficient this may be, having non-standardized string contruction for each message of your overlay can distract from the overal overlay design.
This is the age-old dichotomy of maintainable versus performant code.

The basic class for serializing objects from and to strings/network packets is the ``Serializer`` (``ipv8/messaging/serialization.py``).
Though the ``Serializer`` is extensible, you will mostly only need the default serializer ``default_serializer``.
You can use the ``Serializer`` with classes of the following types:

.. csv-table:: Serializable classes
   :header: "class", "path", "description"
   :widths: 10, 10, 20

   "Serializable", "ipv8/messaging/serialization.py", "Base class for all things serializable. Should support the instance method to_pack_list() and the class method from_unpack_list()."
   "Payload", "ipv8/messaging/payload.py", "Extension of the Serializable class with logic for pretty printing."
   "VariablePayload", "ipv8/messaging/lazy_payload.py", "Less verbose way to specify Payloads, at the cost of performance."


Each of these serializable classes specifies a list of primitive data types it will serialize to and from.
The primitive data types are specified in the :ref:`data types<Datatypes Section>` Section.
Each serializable class has to specify the following class members:

.. csv-table:: Serializable class members
   :header: "member", "description"
   :widths: 10, 20

   "format_list", "A list containing valid data type primitive names."
   "optional_format_list", "A list containing valid data type primitive names. As the name implies, any number of arguments may be supplied."
   "names", "Only for VariablePayload classes, the instance fields to bind the data types to."


As an example, we will now define three completely wire-format compatible messages using the three classes.
Each of the messages will serialize to a (four byte) unsigned integer followed by an optional (two byte) unsigned short.
Each instance will have two fields: ``field1`` and ``field2`` corresponding to the integer and short.

.. code-block:: python

    class MySerializable(Serializable):
        
        format_list = ['I']
        optional_format_list = ['H']

        def __init__(self, field1, field2=None):
            self.field1 = field1
            self.field2 = field2

        def to_pack_list(self):
            out = [('I', self.field1)]
            if self.field2 is not None:
                out += [('H', self.field2)]
            return out

        @classmethod
        def from_unpack_list(cls, *args):
            return cls(*args)


    class MyPayload(Payload):
        
        format_list = ['I']
        optional_format_list = ['H']

        def __init__(self, field1, field2=None):
            self.field1 = field1
            self.field2 = field2

        def to_pack_list(self):
            out = [('I', self.field1)]
            if self.field2 is not None:
                out += [('H', self.field2)]
            return out

        @classmethod
        def from_unpack_list(cls, *args):
            return cls(*args)


    class MyVariablePayload(VariablePayload):
        
        format_list = ['I']
        optional_format_list = ['H']
        names = ['field1', 'field2']


To show some of the differences, let's check out the output of the following script using these definitions:


.. code-block:: python

    serializable1 = MySerializable(1)
    serializable2 = MyPayload(1)
    serializable3 = MyVariablePayload(1)

    print("As string:")
    print(serializable1)
    print(serializable2)
    print(serializable3)

    print("Field values:")
    print(serializable1.field1, serializable1.field2)
    print(serializable2.field1, serializable2.field2)
    print(serializable3.field1, getattr(serializable3, 'field2', '<undefined>'))

    print("Serialization speed:")
    print(timeit.timeit('serializable1.to_pack_list()', number=1000, globals=locals()))
    print(timeit.timeit('serializable2.to_pack_list()', number=1000, globals=locals()))
    print(timeit.timeit('serializable3.to_pack_list()', number=1000, globals=locals()))

    print("Unserialization speed:")
    print(timeit.timeit('serializable1.from_unpack_list(1, 2)', number=1000, globals=locals()))
    print(timeit.timeit('serializable2.from_unpack_list(1, 2)', number=1000, globals=locals()))
    print(timeit.timeit('serializable3.from_unpack_list(1, 2)', number=1000, globals=locals()))

    print("Unserialization speed w/o optional:")
    print(timeit.timeit('serializable1.from_unpack_list(1)', number=1000, globals=locals()))
    print(timeit.timeit('serializable2.from_unpack_list(1)', number=1000, globals=locals()))
    print(timeit.timeit('serializable3.from_unpack_list(1)', number=1000, globals=locals()))


.. code-block:: bash

    As string:
    <__main__.MySerializable object at 0x7f1e25331828>
    MyPayload
    | field1: 1
    | field2: None
    MyVariablePayload
    | field1: 1
    Field values:
    1 None
    1 None
    1 <undefined>
    Serialization speed:
    0.000744990999919537
    0.0007516030000260798
    0.006438396999328688
    Unserialization speed:
    0.001271658999939973
    0.0012590780006576097
    0.021930812000391597
    Unserialization speed w/o optional:
    0.0012806849999833503
    0.00126321699917753
    0.014179239999975835

.. _Datatypes Section:

Datatypes
---------

Next to the unsigned integer and unsigned short data types, the default Serializer has many more data types to offer.
The following table lists all data types available by default, all values are big-endian and most follow the default Python ``struct`` format.
A ``Serializer`` can be extended with arbitrary ``struct`` formats by calling ``serializer.add_packing_format(name, format)`` (for example ``serializer.add_packing_format("I", ">I")``).

.. csv-table:: Available data types
   :header: "member", "bytes", "unserialized type"
   :widths: 5, 5, 20

   "?", 1, "boolean"
   "B", 1, "unsigned byte"
   "BBH", 4, "[unsigned byte, unsigned byte, unsigned short]"
   "BH", 3, "[unsigned byte, unsigned short]"
   "c", 1, "signed byte"
   "f", 4, "signed float"
   "d", 8, "signed double"
   "H", 2, "unsigned short"
   "HH", 4, "[unsigned short, unsigned short]"
   "I", 4, "unsigned integer"
   "l", 4, "signed long"
   "LL", 8, "[unsigned long, unsigned long]"
   "Q", 8, "unsigned long long"
   "QH", 10, "[unsigned long long, unsigned short]"
   "QL", 12, "[unsigned long long, unsigned long]"
   "QQHHBH", 23, "[unsigned long long, unsigned long long, unsigned short, unsigned short, unsigned byte, unsigned long]"
   "ccB", 3, "[signed byte, signed byte, unsigned byte]"
   "4SH", 6, "[str (length 4), unsigned short]"
   "20s", 20, "str (length 20)"
   "32s", 20, "str (length 32)"
   "64s", 20, "str (length 64)"
   "74s", 20, "str (length 74)"
   "c20s", 21, "[unsigned byte, str (length 20)]"
   "bits", 1, "[bit 0, bit 1, bit 2, bit 3, bit 4, bit 5, bit 6, bit 7]"
   "raw", "?", "str (length ?)"
   "varlenBx2", "1 + ? * 2", "[str (length = 2), \.\.\. ] (length < 256)"
   "varlenH", "2 + ?", "str (length ? < 65356)"
   "varlenHx20", "2 + ? * 20", "[str (length = 20), \.\.\. ] (length < 65356)"
   "varlenI", "4 + ?", "str (length < 4294967295)"
   "doublevarlenH", "2 + ?", "str (length ? < 65356)"
   "payload", "2 + ?", "Serializable"


Some of these data types represent common usage of serializable classes:


.. csv-table:: Common data types
   :header: "member", "description"
   :widths: 5, 20

   "4SH", "(IP, port) tuples"
   "20s", "SHA-1 hashes"
   "32s", "libnacl signatures"
   "64s", "libnacl public keys"
   "74s", "libnacl public keys with prefix"


Special instances are the ``raw`` and ``payload`` data types.

- ``raw``: can only be used as the last element in a format list as it will consume the remainder of the input string (avoid if possible).
- ``payload``: will nest another ``Serializable`` instance into this instance. When used, the ``format_list`` should specify the class of the nested ``Serializable`` and the ``to_pack_list()`` output should give a tuple of ``("payload", the_nested_instance)``. The ``VariablePayload`` automatically infers the ``to_pack_list()`` for you. See the ``NestedPayload`` class definition for more info.


The ez_pack family for Community classes
----------------------------------------

All subclasses of the ``EZPackOverlay`` class (most commonly subclasses of the ``Community`` class) have a short-cut for serializing messages belonging to the particular overlay.
This standardizes the prefix and message ids of overlays.
Concretely, it uses the first 23 bytes of each packet to handle versioning and routing (demultiplexing) packets to the correct overlay.

The ``ezr_pack`` method of ``EZPackOverlay`` subclasses takes an (integer) message number and a variable amount of ``Serializable`` instances.
Optionally you can choose to not have the message signed (supply the ``sig=True`` or ``sig=False`` keyword argument for respectively a signature or no signature over the packet).

The ``lazy_wrapper`` and ``lazy_wrapper_unsigned`` decorators can then respectively be used for unserializing payloads which are signed or not signed.
Simply supply the payload classes you wish to unserialize to, to the decorator.

As some internal messages and deprecated messages use some of the message range, you have the messages identifiers from 0 through 234 available for your custom message definitions.
Once you register the message handler and have the appropriate decorator on the specified handler method your overlay can communicate with the Internet.
In practice, given a ``MASTER_KEY`` and the payload definitions ``MyMessagePayload1`` and ``MyMessagePayload2``, this will look something like this example (see `the overlay tutorial <../basics/overlay_tutorial.html>`_ for a complete runnable example):


.. code-block:: python

    class MyCommunity(Community):

        master_peer = Peer(MASTER_KEY)

        def __init__(*args, **kwargs):
            super(MyCommunity, self).__init__(*args, **kwargs)

            self.add_message_handler(1, self.on_message)

        @lazy_wrapper(MyMessagePayload1, MyMessagePayload2)
        def on_message(self, peer, payload1, payload2):
            print("Got a message from:", peer)
            print("The message includes the first payload:\n", payload1)
            print("The message includes the second payload:\n", payload2)

        def send_message(self, peer):
            packet = self.ezr_pack(1, MyMessagePayload1(), MyMessagePayload2())
            self.endpoint.send(peer.address, packet)


It is recommended (but not obligatory) to have single payload messages store the message identifier inside the ``Payload`` instance, as this improves readability:

.. code-block:: python

    self.add_message_handler(MyMessage1.msg_id, self.on_message)
    self.add_message_handler(MyMessage2.msg_id, self.on_message)

    self.ezr_pack(MyMessage1.msg_id, MyMessage1(42))
    self.ezr_pack(MyMessage2.msg_id, MyMessage2(7))


Of course, IPv8 also ships with various ``Community`` subclasses of its own, if you need inspiration.

