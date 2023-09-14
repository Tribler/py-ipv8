"""
Copyright (c), Privacy By Design Foundation
All rights reserved.

This source code has been ported from https://github.com/privacybydesign/irmago
The authors of this file are not -in any way- affiliated with the original authors or organizations.
"""
from __future__ import annotations

import binascii
import calendar
import datetime
import hashlib
import time
from typing import Any

from .....util import int2byte

# ruff: noqa: N801,N802,N803,N806,N816

ExpiryFactor = 60 * 60 * 24 * 7
metadataLength = 1 + 3 + 2 + 2 + 16


class metadataField:
    """
    Metadata position information.
    """

    def __init__(self, length: int, offset: int) -> None:
        """
        Create a new metadata field descriptor.
        """
        self.length = length
        self.offset = offset


versionField = metadataField(1, 0)
signingDateField = metadataField(3, 1)
validityField = metadataField(2, 4)
keyCounterField = metadataField(2, 6)
credentialID = metadataField(16, 8)


def int_to_str(n: int) -> bytes:
    """
    Covert an integer of unbounded size to bytes.
    """
    hexInt = hex(n).lstrip('0x').rstrip('L')
    if (len(hexInt) % 2) == 1:
        hexInt = '0' + hexInt
    return binascii.unhexlify(hexInt)


def shortToByte(x: int) -> bytes:
    """
    Convert a short (stored in a Python int type) to bytes.
    """
    return int_to_str(x)[-2:]


class MetadataAttribute:
    """
    Metadata values.
    """

    def __init__(self, version: bytes) -> None:
        """
        Create a new empty metadata container.
        """
        self.Int = 0
        self.pk = None
        self.Conf = None

        self.setField(versionField, version)
        self.setSigningDate()
        self.setKeyCounter(0)
        self.setExpiryDate()

    def Bytes(self) -> bytes:
        """
        Convert this metadata to bytes.
        """
        bytez = int_to_str(self.Int)
        if len(bytez) < metadataLength:
            bytez += b'\x00' * (metadataLength - len(bytez))
        return bytez

    def setField(self, field: metadataField, value: bytes) -> None:
        """
        Set a given metadata field position to a given value.
        """
        bytez_array = [int2byte(c) if isinstance(c, int) else c for c in self.Bytes()]
        startindex = field.length - len(value)
        for i in range(field.length):
            if i < startindex:
                bytez_array[i + field.offset] = b'\x00'
            else:
                bytez_array[i + field.offset] = value[i - startindex:i - startindex + 1]

        self.Int = int(binascii.hexlify(b''.join(bytez_array)), 16)

    def field(self, field: metadataField) -> bytes:
        """
        Retrieve the value of a given field.
        """
        return self.Bytes()[field.offset:field.offset + field.length]

    def setSigningDate(self, timestamp: int | None = None) -> None:
        """
        Set the date of signing in the metadata.

        Note that the timestamp is a short in units of ``ExpiryFactor``.
        """
        if timestamp:
            self.setField(signingDateField, shortToByte(timestamp))
        else:
            self.setField(signingDateField, shortToByte(int(time.time() / ExpiryFactor)))

    def setKeyCounter(self, i: int) -> None:
        """
        Set the key counter field to a given value.
        """
        self.setField(keyCounterField, shortToByte(i))

    def SigningDate(self) -> int:
        """
        Get the signing date in seconds since the epoch (like ``int(time.time())``).
        """
        bytez_array = [int2byte(c) if isinstance(c, int) else c for c in self.field(signingDateField)]
        bytez_array = bytez_array[1:]
        return int(binascii.hexlify(b''.join(bytez_array)), 16) * ExpiryFactor

    def setValidityDuration(self, weeks: int) -> None:
        """
        Set the value of the validity duration field (in weeks).
        """
        self.setField(validityField, shortToByte(weeks))

    def setExpiryDate(self) -> None:
        """
        Set the default validity duration.
        """
        expiry = datetime.datetime.now()  # noqa: DTZ005
        month = expiry.month - 1 + 6
        year = expiry.year + month // 12
        month = month % 12 + 1
        day = min(expiry.day, calendar.monthrange(year, month)[1])
        fexpiry = time.mktime(datetime.date(year, month, day).timetuple())
        signing = self.SigningDate()
        self.setValidityDuration(int((fexpiry - signing) / ExpiryFactor))

    def setExpiryDateFromTimestamp(self, expiry: float) -> None:
        """
        Set the validity duration from a given expiry timestamp (like ``time.time()``).
        """
        signing = self.SigningDate()
        self.setValidityDuration(int((expiry - signing) / ExpiryFactor))

    def setCredentialTypeIdentifier(self, the_id: bytes) -> None:
        """
        Set the credential type field.
        """
        bytez = hashlib.sha256(the_id).digest()
        self.setField(credentialID, bytez[:16])


def make_attribute_list(cr: dict[str, Any], attribute_order: list[str] | None = None,
                        validity_signing: tuple[int, int | None] | None = None) -> tuple[list[int], int]:
    """
    cr =
        {
            u'attributes': { ... "name": "value" ... },
            u'credential': u'pbdf.nijmegen.address',
            u'keyCounter': 0,
            u'validity': 1570123936
        }.

    :param attribute_order: the order in which to handle the keys
    :type attribute_order: list
    """
    meta = MetadataAttribute(b'\x03')
    meta.setKeyCounter(cr['keyCounter'])
    meta.setCredentialTypeIdentifier(cr['credential'].encode('utf-8'))
    if validity_signing:
        meta.setValidityDuration(validity_signing[0])
        meta.setSigningDate(validity_signing[1])
    else:
        meta.setSigningDate()
        meta.setExpiryDateFromTimestamp(cr['validity'])
    signing_date = int(binascii.hexlify(meta.field(signingDateField)), 16)

    attrs = [meta.Int]
    attr_map = cr["attributes"]
    attribute_order = attribute_order or attr_map.keys()

    for k in attribute_order:
        if attr_map.get(k, None) is None:
            attrs.append(0)
        elif not attr_map[k]:
            attrs.append(1)
        else:
            encoded = attr_map[k].encode('utf-8')
            v = int(binascii.hexlify(b''.join(int2byte(c) if isinstance(c, int) else c for c in encoded)), 16)
            v <<= 1
            v += 1
            attrs.append(v)

    return attrs, signing_date
