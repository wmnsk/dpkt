# -*- coding: utf-8 -*-
"""MTP2-User Peer-to-Peer Adaptation Layer."""

from __future__ import print_function
from __future__ import absolute_import

import struct

from . import dpkt
from .compat import compat_ord


# Signaling System 7 (SS7) Message Transfer Part 2 (MTP2)
# User Peer-to-Peer Adaptation Layer (M2PA) - RFC4165
# https://tools.ietf.org/html/rfc4165


# M2PA Message Types
TYPE_USER_DATA = 1
TYPE_LINK_STATUS = 2


class M2PA(dpkt.Packet):
    """M2PA Common Header.

    Attributes:
        __hdr__: M2PA Common Header fields. Supported fields are;
                  - ver: M2PA version. "1" is only supported.
                  - spare: Field for spare. Always "0".
                  - class: M2PA message class. Always "11".
                  - type: User Data("1") or Link Status("2").
                  - len: Length of the message in octets.
    """

    __hdr__ = (
        ('ver', 'B', 1),
        ('spare', 'B', 0),
        ('cls', 'B', 11),
        ('type', 'B', TYPE_USER_DATA),
        ('len', 'I', 0)
    )

    def pack_hdr(self):
        self.len = self.__hdr_len__ + len(bytes(self.data))
        return dpkt.Packet.pack_hdr(self)


class M2PAHeader(dpkt.Packet):
    """M2PA-Specific Header.

    Attributes:
        __hdr__: M2PA-Specific Header fields. Supported fields are;
                  - u1: Unsused field before BSN.
                  - bsn: Backward Sequence Number, usually filled with FSN that
                         received last from the peer.
                  - u2: M2PA message class. Always "11".
                  - fsn: Forward Sequence Number, indicates the number of
                         User Data type messages being sent.
        priority: Optional field, used when M2PA type is User Data and
                  used only in national MTP defined in TTC(Japan) format.
                  Otherwise, this field is not used(regarded as spare).
    """

    __hdr__ = (
        ('u1', 'B', 0),
        ('bsn', '3s', 0),
        ('u2', 'B', 0),
        ('fsn', '3s', 0)
    )

    @property
    def priority(self):
        return ord(self.data[:2])

    @priority.setter
    def priority(self, p):
        self.data = self.data[:-2] + struct.pack('B', p)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)

        # convert byte to integer.
        b2i = lambda x: (
            (compat_ord(x[0]) << 16) |
            (compat_ord(x[1]) << 8) |
            (compat_ord(x[2]))
            )
        self.bsn = b2i(self.bsn)
        self.fsn = b2i(self.fsn)

    def pack_hdr(self):
        # convert integer to bytes
        i2b = lambda x: struct.pack('BBB',
            (x >> 16) & 0xff,
            (x >> 8) & 0xff,
            x & 0xff
            )
        self.bsn = i2b(self.bsn)
        self.fsn = i2b(self.fsn)
        return dpkt.Packet.pack_hdr(self)


__common = b'\x01\x00\x0b\x01\x00\x00\x00\x08'
__with_itu = b'\x01\x00\x0b\x01\x00\x00\x00\x10\x00\x00\x00\x07\x00\x00\x00\x08'
__with_ttc = b'\x01\x00\x0b\x01\x00\x00\x00\x11\x00\x00\x00\x07\x00\x00\x00\x08\xfe'


def test_pack():
    """Packing test.
    Create M2PA/M2PAHeader instance by inserting values to the fields
    manually, then check if the values are expectedly set and the
    payload as a whole is the same as the bytearray above.
    """

    m = M2PA(ver=1, spare=0, cls=11, type=TYPE_USER_DATA)
    assert (bytes(m) == __common)

    h = M2PAHeader(u1=0, bsn=7, u2=0, fsn=8)
    m.data = bytes(h)
    assert (bytes(m) == __with_itu)

    m2 = M2PA(ver=1, spare=0, cls=11, type=TYPE_USER_DATA)
    h2 = M2PAHeader(u1=0, bsn=7, u2=0, fsn=8)
    h2.priority = 254
    m2.data = bytes(h2)
    assert (bytes(m2) == __with_ttc)


def test_unpack():
    """Unpacking test.
    Create MTP3 instance by loading the bytearray above and
    check if the values are expectedly decoded.
    """

    m = M2PA(__with_ttc)
    assert (m.ver == 1)
    assert (m.spare == 0)
    assert (m.cls == 11)
    assert (m.len == 17)

    h = M2PAHeader(m.data)
    assert (h.u1 == 0)
    assert (h.bsn == 7)
    assert (h.u2 == 0)
    assert (h.fsn == 8)
    assert (h.priority == 254)
