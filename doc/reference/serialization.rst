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
   "dataclass", "ipv8/messaging/payload_dataclass.py", "Use dataclasses to send messages, at the cost of control and performance."


Other than the ``dataclass``, each of these serializable classes specifies a list of primitive data types it will serialize to and from.
The primitive data types are specified in the :ref:`data types<Datatypes Section>` Section.
Each serializable class has to specify the following class members (``dataclass`` does this automatically):

.. csv-table:: Serializable class members
   :header: "member", "description"
   :widths: 10, 20

   "format_list", "A list containing valid data type primitive names."
   "names", "Only for VariablePayload classes, the instance fields to bind the data types to."


As an example, we will now define four completely wire-format compatible messages using the four classes.
Each of the messages will serialize to a (four byte) unsigned integer followed by an (two byte) unsigned short.
If the ``dataclass`` had used normal ``int`` types, these would have been two signed 8-byte integers instead.
Each instance will have two fields: ``field1`` and ``field2`` corresponding to the integer and short.

.. literalinclude:: serialization_1.py
   :lines: 9-61


To show some of the differences, let's check out the output of the following script using these definitions:


.. literalinclude:: serialization_1.py
   :lines: 64-75


.. code-block:: bash

    As string:
    <__main__.MySerializable object at 0x7f732a23c1f0>
    MyPayload
    | field1: 1
    | field2: 2
    MyVariablePayload
    | field1: 1
    | field2: 2
    MyCVariablePayload
    | field1: 1
    | field2: 2
    MyDataclassPayload
    | field1: 1
    | field2: 2


.. _Datatypes Section:

Datatypes
---------

Next to the unsigned integer and unsigned short data types, the default Serializer has many more data types to offer.
The following table lists all data types available by default, all values are big-endian and most follow the default Python ``struct`` format.
A ``Serializer`` can be extended with additional data types by calling ``serializer.add_packer(name, packer)``, where ``packer`` represent the object responsible for (un)packing the data type. The most commonly used packer is ``DefaultStruct``, which can be used with arbitrary ``struct`` formats (for example ``serializer.add_packer("I", DefaultStruct(">I"))``).

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
   "q", 8, "signed long long"
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
   "ipv4", 6, "[str (length 7-15), unsigned short]"
   "raw", "?", "str (length ?)"
   "varlenBx2", "1 + ? * 2", "[str (length = 2), \.\.\. ] (length < 256)"
   "varlenH", "2 + ?", "str (length ? < 65356)"
   "varlenHutf8", "2 + ?", "str (encoded length ? < 65356)"
   "varlenHx20", "2 + ? * 20", "[str (length = 20), \.\.\. ] (length < 65356)"
   "varlenH-list", "1 + ? * (2 + ??)", "[str (length < 65356)] (length < 256)"
   "varlenI", "4 + ?", "str (length < 4294967295)"
   "doublevarlenH", "2 + ?", "str (length ? < 65356)"
   "payload", "2 + ?", "Serializable"
   "payload-list", "?", "[Serializable]"
   "arrayH-?", "2 + ? * 1", "[bool]"
   "arrayH-q", "2 + ? * 8", "[int]"
   "arrayH-d", "2 + ? * 8", "[float]"

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
In practice, given a ``COMMUNITY_ID`` and the payload definitions ``MyMessagePayload1`` and ``MyMessagePayload2``, this will look something like this example (see `the overlay tutorial <../basics/overlay_tutorial.html>`_ for a complete runnable example):


.. literalinclude:: serialization_2.py
   :lines: 24-40

It is recommended (but not obligatory) to have single payload messages store the message identifier inside the ``Payload.msg_id`` field, as this improves readability:

.. literalinclude:: serialization_3.py
   :lines: 32,33,54,57
   :dedent: 4

If you are using the ``@dataclass`` wrapper you can specify the message identifier through an argument instead.
For example, ``@dataclass(msg_id=42)`` would set the message identifier to ``42``.

Of course, IPv8 also ships with various ``Community`` subclasses of its own, if you need inspiration.


Using external serialization options
------------------------------------

IPv8 is compatible with pretty much all third-party message serialization packages.
However, before hooking one of these packages into IPv8 you may want to ask yourself whether you have fallen victim to marketing hype.
After all, ``XML`` is the one unifying standard we will never switch away from, right?
Oh wait, no, it's ``JSON``.
My bad, it's ``Protobuf``.
Or was it ``ASN.1``?
You get the point.
In this world, only the core ``IPv8`` serialization format remains constant.

There are three main ways to hook in external serialization: *per message*, *per Serializer* and *per Community*.
The three methods can be freely mixed.

Custom serialization per message
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you only want to use custom seralization for (part of) a single overlay message, you can use ``VariablePayload`` field modification (this also works for dataclass payloads).
This method involves implementing the methods ``fix_pack_<your field name>`` and ``fix_unpack_<your field name>`` for the fields of your message that use custom serialization.
Check out the following example:

.. literalinclude:: serialization_4.py
   :lines: 11-36

In both classes we create a message with a single field ``dictionary``.
To pack this field, we use ``json.dumps()`` to create a string representation of the dictionary.
When loading a message, ``json.loads()`` is used to create a dictionary from the serialized data.
Instead of ``json`` you could also use any serialization of your liking.

Using the same transformations for all fields makes your payloads very lengthy.
In this case, you may want to look into specifying a custom serialization format.

Custom serialization formats
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is possible to specify new formats by adding packing formats to a ``Serializer`` instance.
You can easily do so by overwriting your ``Community.get_serializer()`` method.
This ``Serializer`` is sandboxed per ``Community`` instance, so you don't have to worry about breaking other instances.
Check out the following example and note that the message is now much smaller at the expense of having to define a custom (complicated) packing format.

.. literalinclude:: serialization_5.py
   :lines: 16-48

The line ``serializer.add_packer('json', PackerJSON())`` adds the new format ``json`` that is used in ``Message``.
In fact, any further message added to this ``Community`` can now use the ``json`` format.
However, you may also note some additional complexity in the ``PackerJSON`` class.

Our custom packer ``PackerJSON`` implements two required methods: ``pack()`` and ``unpack()``.
The former serializes data using custom serialization (``json.dumps()`` in this case).
We use a big-endian unsigned short (``">H"``) to determine the length of the serialized JSON data.
The ``unpack()`` method creates JSON objects from the serialized data, returning the new offset in the ``data`` stream and adding the object ot the ``unpack_list`` list.

Custom Community data handling
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is possible to circumvent IPv8 message formats altogether.
In its most extreme form, you can overwrite ``Community.on_packet(packet)`` to inspect all raw data sent to your ``Community`` instance.
The ``packet`` is a tuple of ``(source_address, data)``.
You can write raw data back to an address using ``self.endpoint.send(address, data)``.

If you want to mix with other messages, you should use the message byte.
The following example shows how to use JSON serialization without any IPv8 serialization.
Note that we need to do our own signature checks now.

.. literalinclude:: serialization_6.py
   :lines: 16-46


Nested Payloads
---------------

It is possible to put a ``Payload`` inside another ``Payload``.
We call these nested payloads.
You can specify them by using the ``"payload"`` datatype and setting the ``Payload`` class in the format list.
For a ``VariablePayload`` this looks like the following example.

.. literalinclude:: serialization_7.py
   :lines: 5-12

For dataclass payloads this nesting is supported by simply specifying nested classes as follows.

.. literalinclude:: serialization_7.py
   :lines: 15-24
