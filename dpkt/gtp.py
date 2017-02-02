# -*- coding: utf-8 -*-
"""General Packet Radio System (GPRS) Tunneling Protocol (GTP)."""

from __future__ import absolute_import

import struct

from . import dpkt
from .compat import compat_ord
from binascii import hexlify as hx

# General Packet Radio Service (GPRS); GPRS Tunnelling Protocol (GTP)
# across the Gn and Gp interface
# https://www.3gpp.org/DynaReport/29060.htm
# 
# General Packet Radio System (GPRS) Tunnelling Protocol User Plane (GTPv1-U)
# https://www.3gpp.org/DynaReport/29281.htm
#
# 3GPP Evolved Packet System (EPS);
# Evolved General Packet Radio Service (GPRS) Tunnelling Protocol
# for Control plane (GTPv2-C); Stage 3 
# https://www.3gpp.org/DynaReport/29274.htm
# 
# Telecommunication management; Charging management;
# Charging Data Record (CDR) transfer
# https://www.3gpp.org/DynaReport/32295.htm


# GTPv2 Message Types
V2_RESERVED = 0
V2_ECHO_REQ = 1
V2_ECHO_RES = 2
V2_VER_NOT_SUPPORTED = 3
V2_CREATE_SESSION_REQ = 32
V2_CREATE_SESSION_RES = 33
V2_MODIFY_BEARER_REQ = 34
V2_MODIFY_BEARER_RES = 35
V2_DELETE_SESSION_REQ = 36
V2_DELETE_SESSION_RES = 37
V2_CHANGE_NOTIFICATION_REQ = 38
V2_CHANGE_NOTIFICATION_RES = 39
V2_REMOTE_UE_REPORT_NOTIFY = 40
V2_REMOTE_UE_REPORT_ACK = 41
V2_MODIFY_BEARER_CMD = 64
V2_MODIFY_BEARER_FAIL = 65
V2_DELETE_BEARER_CMD = 66
V2_DELETE_BEARER_FAIL = 67
V2_BEARER_RESOURCE_CMD = 68
V2_BEARER_RESOURCE_FAIL = 69
V2_DL_DATA_NOTE_FAIL = 70
V2_TRACE_SESSION_ACT = 71
V2_TRACE_SESSION_DEACT = 72
V2_STOP_PAGING_INDICATION = 73
V2_CREATE_BEARER_REQ = 95
V2_CREATE_BEARER_RES = 96
V2_UPDATE_BEARER_REQ = 97
V2_UPDATE_BEARER_RES = 98
V2_MODIFY_BEARER_REQ = 99
V2_MODIFY_BEARER_RES = 100
V2_DELETE_PDN_CONN_SET_REQ = 101
V2_DELETE_PDN_CONN_SET_RES = 102
V2_PGW_DL_TRIGGER_NOTIFY = 103
V2_PGW_DL_TRIGGER_ACK = 104
V2_INDICATION_REQ = 128
V2_INDICATION_RES = 129
V2_CONTEXT_REQ = 130
V2_CONTEXT_RES = 131
V2_CONTEXT_ACK = 132
V2_FORWARD_RELOC_REQ = 133
V2_FORWARD_RELOC_RES = 134
V2_FORWARD_RELOC_COMPLETE_REQ = 135
V2_FORWARD_RELOC_COMPLETE_REQ = 136
V2_FORWARD_ACCESS_CONTEXT_NOTIFY = 137
V2_FORWARD_ACCESS_CONTEXT_ACK = 138
V2_RELOC_CANCEL_REQ = 139
V2_RELOC_CANCEL_RES = 140
V2_CONFIG_TRANSFER_TUNNEL = 141
V2_DETACH_NOTIFY = 149
V2_DETACH_ACK = 150
V2_CS_PAGING_INDICATION = 151
V2_RAN_INFO_RELAY = 152
V2_ALERT_MME_NOTIFY = 153
V2_ALERT_MME_ACK = 154
V2_UE_ACTIVITY_NOTIFY = 155
V2_UE_ACTIVITY_ACK = 156
V2_ISR_STATUS_INDICATION = 157
V2_UE_REGIST_QUERY_REQ = 158
V2_UE_REGIST_QUERY_RES = 159
V2_CREATE_FORWARDING_TUNNEL_REQ = 160
V2_CREATE_FORWARDING_TUNNEL_RES = 161
V2_SUSPEND_NOTIFY = 162
V2_SUSPEND_NOTIFY = 163
V2_RESUME_NOTIFY = 164
V2_RESUME_ACK = 165
V2_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQ = 166
V2_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RES = 167
V2_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_REQ = 168
V2_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RES = 169
V2_RELEASE_ACCESS_BEARERS_REQ = 170
V2_RELEASE_ACCESS_BEARERS_RES = 171
V2_DL_DATA_NOTIFY = 176
V2_DL_DATA_NOTIFY_ACK = 177
V2_PGW_RESTART_NOTIFY = 179
V2_PGW_RESTART_ACK = 180
V2_UPDATE_PDN_CONN_SET_REQ = 200
V2_UPDATE_PDN_CONN_SET_RES = 201
V2_MODIFY_ACCESS_BEARERS_REQ = 211
V2_MODIFY_ACCESS_BEARERS_RES = 212
V2_MBMS_SESSION_START_REQ = 231
V2_MBMS_SESSION_START_RES = 232
V2_MBMS_SESSION_UPDATE_REQ = 233
V2_MBMS_SESSION_UPDATE_RES = 234
V2_MBMS_SESSION_STOP_REQ = 235
V2_MBMS_SESSION_STOP_RES = 236


class GTPv1C(dpkt.Packet):
    """GTPv1-C Header.

    Attributes:
        __hdr__  : GTPv2-C header in general format
                    - flags: Version, Piggyback flag, TEID flag, and spare bits
                    - type : GTPv2-C Message Type
                    - len  : length of whole payload
        teid     : Tunnel Endpoint Identifier
        seqnum   : Sequence Number
        ndpu     : N-PDU Number
        next_type:  Next Extension Header Type
    """
    __hdr__ = (
        ('flags', 'B', 0),
        ('type', 'B', 0),
        ('len', 'H', 0),
        ('teid', 'I', 0),
    )

    @property
    def version(self):
        return (self.flags >> 5) & 0x7

    @version.setter
    def version(self, v):
        self.flags = (self.flags & ~0xe0) | ((v & 0x7) << 5)

    @property
    def proto_type(self):
        return (self.flags >> 4) & 0x1

    @proto_type.setter
    def proto_type(self, p):
        self.flags = (self.flags & ~0x10) | ((p & 0x1) << 4)

    @property
    def e_flag(self):
        return (self.flags >> 2) & 0x1

    @e_flag.setter
    def e_flag(self, e):
        self.flags = (self.flags & ~0x4) | ((e & 0x1) << 2)

    @property
    def s_flag(self):
        return (self.flags >> 1) & 0x1

    @s_flag.setter
    def s_flag(self, s):
        self.flags = (self.flags & ~0x2) | ((s & 0x1) << 1)

    @property
    def np_flag(self):
        return self.flags & 0x1

    @np_flag.setter
    def np_flag(self, n):
        self.flags = (self.flags & ~0x1) | (n & 0x1)

    @property
    def __additionals(self):
        return self.flags & 0x7

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)

        if self.__additionals:
            self.seqnum = (
                (compat_ord(self.data[0]) << 8) |
                (compat_ord(self.data[1]))
            )
            self.npdu = compat_ord(self.data[2])
            self.next_type = compat_ord(self.data[3])
            self.data = self.data[5:]

        l = []
        while self.data:
            ie = InfoElement(self.data)
            l.append(ie)
            self.data = self.data[len(ie):]
        self.data = self.ies = l

    def pack_hdr(self):
        if self.__additionals:
            self.seqnum = struct.pack('BB',
                (self.seqnum >> 8) & 0xff,
                (self.seqnum) & 0xff,
            )
            self.npdu = struct.pack('B', self.npdu & 0xff)
            self.next_type = struct.pack('B', self.next_type & 0xff)
        else:
            self.seqnum = self.npdu = self.next_type = b''

        self.data = self.seqnum + self.npdu + self.next_type + b''.join([bytes(d) for d in self.data])
        self.len = len(self.data)

        return dpkt.Packet.pack_hdr(self)


class GTPv2C(dpkt.Packet):
    """GTPv2-C Header.

    Attributes:
        __hdr__ : GTPv2-C header in general format
                   - flags: Version, Piggyback flag, TEID flag, and spare bits
                   - type : GTPv2-C Message Type
                   - len  : length of whole payload
        teid    : Tunnel Endpoint Identifier
        seqnum  : Sequence Number
        priority: Message Priority
    """
    __hdr__ = (
        ('flags', 'B', 0),
        ('type', 'B', 0),
        ('len', 'H', 0),
    )

    @property
    def version(self):
        return (self.flags >> 5) & 0x7

    @version.setter
    def version(self, v):
        self.flags = (self.flags & ~0xe0) | ((v & 0x7) << 5)

    @property
    def p_flag(self):
        return (self.flags >> 4) & 0x1

    @p_flag.setter
    def p_flag(self, p):
        self.flags = (self.flags & ~0x10) | ((p & 0x1) << 4)

    @property
    def t_flag(self):
        return (self.flags >> 3) & 0x1

    @t_flag.setter
    def t_flag(self, t):
        self.flags = (self.flags & ~0x8) | ((t & 0x1) << 3)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)

        if self.t_flag:
            self.teid = (
                (compat_ord(self.data[0]) << 24) |
                (compat_ord(self.data[1]) << 16) |
                (compat_ord(self.data[2]) << 8) |
                (compat_ord(self.data[3]))
            )
            self.seqnum = (
                (compat_ord(self.data[4]) << 16) |
                (compat_ord(self.data[5]) << 8) |
                (compat_ord(self.data[6]))
            )
            self.priority = (compat_ord(self.data[7]) >> 4) & 0xf
            self.data = self.data[8:]
        else:
            self.seqnum = self.data[:3]
            # self.spare = self.data[4]
            self.data = self.data[5:]

        l = []
        while self.data:
            ie = InfoElement(self.data)
            l.append(ie)
            self.data = self.data[len(ie):]
        self.data = self.ies = l

    def pack_hdr(self):
        if self.t_flag:
            self.teid = struct.pack('4B',
                (self.teid >> 24) & 0xff,
                (self.teid >> 16) & 0xff,
                (self.teid >> 8) & 0xff,
                (self.teid) & 0xff,
            )
        else:
            self.teid = b''

        self.seqnum = struct.pack('3B',
            (self.seqnum >> 16) & 0xff,
            (self.seqnum >> 8) & 0xff,
            (self.seqnum) & 0xff,
        )

        self.data = self.teid + self.seqnum + b'\x00' + b''.join([bytes(d) for d in self.data])
        self.len = len(self.data)

        return dpkt.Packet.pack_hdr(self)


class InfoElement(dpkt.Packet):
    """docstring for InfoElement

    Attributes:
        __hdr__ : Information Element Header.
                   - type : IE Type
                   - len  : length
                   - flags: CR flag and Instance
    """
    __hdr__ = (
        ('type', 'B', 0),
        ('len', 'H', 0),
        ('flags', 'B', 0),
    )

    @property
    def cr_flag(self):
        return (self.flags >> 4) & 0xf

    @cr_flag.setter
    def cr_flag(self, c):
        pass

    @property
    def instance(self):
        return self.flags & 0xf

    @instance.setter
    def instance(self, c):
        pass

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = self.data[:self.len]

    def pack_hdr(self):
        self.len = len(self.data)
        return dpkt.Packet.pack_hdr(self)


__v1c_payloads = [
    b'2 \x00%\x00\x00\x00\x10\x00\n\xca\xfe', # Header
    b'\x01\x00\x08\x00D\x90\x01\x12#4E\xf5', #IMSI
    b'G\x00\x11\x00some.operator.net' # APN
]

__v1c = b''.join(__v1c_payloads)

__v2c_payloads = [
    b'H \x00\x29\x00\x00\x00\x10\x01\x00\n\x00', # Header
    b'\x01\x00\x08\x00D\x90\x01\x12#4E\xf5', #IMSI
    b'G\x00\x11\x00some.operator.net' # APN
]

__v2c = b''.join(__v2c_payloads)


def test_unpack():
    v2c = GTPv2C(__v2c)
    assert (v2c.version == 2)
    assert (v2c.p_flag == 0)
    assert (v2c.t_flag == 1)
    assert (v2c.type == V2_CREATE_SESSION_REQ)
    assert (v2c.len == 41)
    assert (v2c.teid == 0x00000010)
    assert (v2c.seqnum == 0x0001000a)

    imsi = v2c.ies[0]
    assert (imsi.type == 1)
    assert (imsi.len == 8)
    assert (imsi.cr_flag == 0)
    assert (imsi.instance == 0)
    assert (imsi.data == b'D\x90\x01\x12#4E\xf5')

    apn = v2c.ies[1]
    assert (apn.type == 71)
    assert (apn.len == 17)
    assert (apn.cr_flag == 0)
    assert (apn.instance == 0)
    assert (apn.data == b'some.operator.net')

    v1c = GTPv1C(__v1c)
    assert (v1c.version == 1)
    assert (v1c.proto_type == 1)
    assert (v1c.e_flag == 0)
    assert (v1c.s_flag == 1)
    assert (v1c.np_flag == 0)
    assert (v1c.type == V2_CREATE_SESSION_REQ)
    assert (v1c.len == 37)
    assert (v1c.teid == 0x00000010)
    assert (v1c.seqnum == 0x0001000a)
    assert (v1c.npdu == 0xca)
    assert (v1c.next_type == 0xfe)

    imsi = v1c.ies[0]
    assert (imsi.type == 1)
    assert (imsi.len == 8)
    assert (imsi.cr_flag == 0)
    assert (imsi.instance == 0)
    assert (imsi.data == b'D\x90\x01\x12#4E\xf5')

    apn = v1c.ies[1]
    assert (apn.type == 71)
    assert (apn.len == 17)
    assert (apn.cr_flag == 0)
    assert (apn.instance == 0)
    assert (apn.data == b'some.operator.net')

def test_pack():
    v1c = GTPv1C(
        version=1,
        proto_type=1,
        e_flag=0,
        s_flag=1,
        np_flag=0,
        type=V2_CREATE_SESSION_REQ,
        teid=0x00000010,
        seqnum=0x0001000a,
        npdu=0xca,
        next_type=0xfe
        )

    v2c = GTPv2C(
        version=2,
        p_flag=0,
        t_flag=1,
        type=V2_CREATE_SESSION_REQ,
        teid=0x00000010,
        seqnum=0x0001000a
        )

    infoelems = [
        InfoElement(
            type=1,
            cr_flag=0,
            instance=0,
            data=b'D\x90\x01\x12#4E\xf5'
        ),
        InfoElement(
            type=71,
            cr_flag=0,
            instance=0,
            data=b'some.operator.net'
        )
    ]

    v1c.data = infoelems
    assert (bytes(v1c) == __v1c)

    v2c.data = infoelems
    assert (bytes(v2c) == __v2c)
