# -*- coding: utf-8 -*-
"""Signaling System 7 (SS7) Message Transfer Part 2 (MTP2)"""

from __future__ import print_function
from __future__ import absolute_import

import struct

from . import dpkt
from .compat import compat_ord


# MTP2-User Peer-to-Peer Adaptation Layer (M2PA) - rfc4165
# https://tools.ietf.org/html/rfc4165


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
        ('type', 'B', 1),
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
    1. Check if M2PA Common Header with no additional data created manually
       has the expected values and is the same as bytearray(__common).
    2. Check if M2PA Header created manually has the expected values.
    3. Put M2PA Header on M2PA Common Header as .data, and check if the
       whole payload is the same as bytearray(__with_itu)
    4. Add priority field which only exists in TTC-formatted M2PA Header,
       and check if the whole payload is the same as bytearray(__with_ttc).
    """

    m = M2PA(ver=1, spare=0, cls=11, type=1)
    assert (bytes(m) == __common)

    h = M2PAHeader(u1=0, bsn=7, u2=0, fsn=8)
    m.data = bytes(h)
    assert (bytes(m) == __with_itu)

    m2 = M2PA(ver=1, spare=0, cls=11, type=1)
    h2 = M2PAHeader(u1=0, bsn=7, u2=0, fsn=8)
    h2.priority = 254
    m2.data = bytes(h2)
    assert (bytes(m2) == __with_ttc)


def test_unpack():
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
