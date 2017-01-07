# -*- coding: utf-8 -*-
"""Message Transfer Part Level 3."""

from __future__ import print_function
from __future__ import absolute_import

import struct

from . import dpkt
from .compat import compat_ord


# Message Transfer Part Level 3 defined in Q.704


# Network Indicators
NI_INTERNATINAL = 0
NI_NATIONAL = 2
NI_RSV_NATIONAL = 3

# Service Indicators
SI_MGMT = 0
SI_MAINT = 1
SI_SCCP = 3
SI_TUP = 4
SI_ISUP = 5
SI_DUP_CALL = 6
SI_DUP_CANCEL = 7
SI_RSV_TEST = 8
SI_BB_ISUP = 9
SI_SATEL_ISUP = 10


class MTP3(dpkt.Packet):
    """Message Transfer Part Level 3(MTP3).
    MTP3 is responsible for routing packets in SS7 network.

    Attributes:
        __hdr__: Header fields of MTP3.
                  - service_info  : Service Information Octet
                     - ni : Network Indicator. Indicates international or national.
                     - si : Service Indicator. Indicates what kind of data is on MTP3.
                  - routing_label : Routing Label
                     - dpc : Destination Point Code.
                     - opc : Originating Point Code
                     - sls : Signaling Link Selection.
    """

    __hdr__ = (
        ('service_info', 'B', 0),
        ('routing_label', '5s', 0),
    )

    @property
    def ni(self):
        return (self.service_info >> 6) & 0x2

    @ni.setter
    def ni(self, n):
        self.service_info = (self.service_info & ~0x80) | ((n & 0x2) << 6)

    @property
    def si(self):
        return self.service_info & 0x3

    @si.setter
    def si(self, s):
        self.service_info = self.service_info | (s & 0x3)

    @property
    def dpc(self):
        return (self.routing_label >> 24) & 0xffff

    @dpc.setter
    def dpc(self, d):
        self.routing_label = self.routing_label | ((d & 0xffff) << 24)

    @property
    def opc(self):
        return (self.routing_label >> 8) & 0xffff

    @opc.setter
    def opc(self, s):
        self.routing_label = (self.routing_label & ~0xffff00) | ((s & 0xffff) << 8)

    @property
    def sls(self):
        return self.routing_label & 0xff

    @sls.setter
    def sls(self, s):
        self.routing_label = (self.routing_label & ~0xff) | ((s & 0xff))

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.routing_label = (
            (compat_ord(self.routing_label[0]) << 32) |
            (compat_ord(self.routing_label[1]) << 24) |
            (compat_ord(self.routing_label[2]) << 16) |
            (compat_ord(self.routing_label[3]) << 8) |
            (compat_ord(self.routing_label[4]))
        )
        self.len = len(self.data) + self.__hdr_len__

    def pack_hdr(self):
        self.routing_label = struct.pack("BBBBB",
            (self.routing_label >> 32) & 0xff,
            (self.routing_label >> 24) & 0xff,
            (self.routing_label >> 16) & 0xff,
            (self.routing_label >> 8) & 0xff,
            (self.routing_label) & 0xff,
        )
        return dpkt.Packet.pack_hdr(self)


__s = b'\x83b(!\x04\t\xde\xad\xbe\xef'


def test_pack():
    """Packing test.
    Create empty MTP3 instance and insert values to the
    fields manually, then check if the payload as a whole
    is the same as the bytearray above.
    """

    mtp3 = MTP3()
    mtp3.ni = NI_NATIONAL
    mtp3.si = SI_SCCP
    mtp3.dpc = 25128
    mtp3.opc = 8452
    mtp3.sls = 9
    mtp3.data = b'\xde\xad\xbe\xef'

    assert (__s == bytes(mtp3))


def test_unpack():
    """Packing test.
    Create MTP3 instance by loading the bytearray above and
    check if the values are expectedly decoded.
    """

    mtp3 = MTP3(__s)

    assert (mtp3.ni == NI_NATIONAL)
    assert (mtp3.si == SI_SCCP)
    assert (mtp3.dpc == 25128)
    assert (mtp3.opc == 8452)
    assert (mtp3.sls == 9)
    assert (mtp3.data == b'\xde\xad\xbe\xef')
