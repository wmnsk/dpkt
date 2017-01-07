# -*- coding: utf-8 -*-
"""Signaling System 7 (SS7) Message Transfer Part 3 (MTP3)"""

from __future__ import print_function
from __future__ import absolute_import

import struct

from . import dpkt


# MTP3-User Adaptation Layer (M3UA) - rfc4688
# https://tools.ietf.org/html/rfc4688


# M3UA Parameter Tags
M3UA_INFO_STRING = 4
M3UA_ROUTING_CXT = 6
M3UA_DIAG_INFO = 7
M3UA_HEARTBEAT_DATA = 9
M3UA_TRAFFIC_MODE_TYPE = 11
M3UA_ERROR_CODE = 12
M3UA_STATUS = 13
M3UA_ASP_ID = 17
M3UA_AFFECTED_PC = 18
M3UA_CORRELATION_ID = 19
M3UA_NETWORK_APPEARANCE = 512
M3UA_USER_CAUSE = 516
M3UA_CONG_INDICATIONS = 517
M3UA_CONCERNED_DST = 518
M3UA_ROUTING_KEY = 519
M3UA_REGIST_RESULT = 520
M3UA_DEREGIST_RESULT = 521
M3UA_LOCAL_ROUTING_KEY_ID = 522
M3UA_DST_PC = 523
M3UA_SERVICE_INDICATORS = 524
M3UA_ORG_PC_LIST = 526
M3UA_PROTOCOL_DATA = 528
M3UA_REGIST_STATUS = 530
M3UA_DEREGIST_STATUS = 531

# MTP3 Network Indicators
PD_NI_INTERNATINAL = 0
PD_NI_NATIONAL = 2
PD_NI_RSV_NATIONAL = 3

# MTP3 Service Indicators
PD_SI_MGMT = 0
PD_SI_MAINT = 1
PD_SI_SCCP = 3
PD_SI_TUP = 4
PD_SI_ISUP = 5
PD_SI_DUP_CALL = 6
PD_SI_DUP_CANCEL = 7
PD_SI_RSV_TEST = 8
PD_SI_BB_ISUP = 9
PD_SI_SATEL_ISUP = 10


class M3UA(dpkt.Packet):
    """M3UA Common Header.

    Attributes:
        __hdr__: M3UA Common Header fields. Supported fields are;
                  - ver: M3UA version. "1" is only supported.
                  - rsv: Reserved field. Always "0".
                  - class: M3UA message class.
                  - type: M3UA message type.
                  - len: Length of the message in octets.
                         This indicates the length of not only M3UA itself's
                         but ALL upper layers', including spare and unused fields.
    """

    __hdr__ = (
        ('ver', 'B', 1),
        ('rsv', 'B', 0),
        ('cls', 'B', 0),
        ('type', 'B', 0),
        ('len', 'I', 0)
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = self.data[:self.len - self.__hdr_len__]

        l = []
        while self.data:
            ptype = struct.unpack('>H', self.data[:2])[0]
            param = PARAM_TYPES_DICT.get(ptype, M3UAParam)(self.data)
            l.append(param)
            self.data = self.data[len(param):]
        self.data = self.params = l

    def pack_hdr(self):
        l = []
        for d in self.data:
            padlen = 0 if len(d) % 4 == 0 else 4 - (len(d) % 4)
            padding = b'\x00' * padlen
            l.append(bytes(d) + padding)
        self.data = self.params = b''.join(l)

        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class M3UAParam(dpkt.Packet):
    """M3UA Variable Length Parameter.

    Attributes:
        __hdr__: Variable Length Parameter fields. Supported fields are;
                  - tag: Parameter tag.
                  - len: Parameter length.
    """

    __hdr__ = (
        ('tag', 'H', 1),
        ('len', 'H', 0)
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        padlen = 0 if self.len % 4 == 0 else 4 - (self.len % 4)

        self.value = self.data[:self.len - self.__hdr_len__]
        self.data = self.data[:self.len + padlen - self.__hdr_len__]

    def pack_hdr(self):
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamProtocolData(M3UAParam):
    """M3UA Protocol Data parameter.
    This parameter has the fields equivalent to the original MTP3.
    Supported fields are;
     - Parameter Tag
     - Parameter length
     - Originating Point Code
     - Destination Point Code
     - Service Indicator
     - Network Indicator
     - Message Priority
     - Signaling Link Selection

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
        __hdr_spec__: Parameter-specific fields of M3UA.

    TODO: Implement other parameters.
    """
    __hdr_spec__ = (
        ('opc', 'I', 0),
        ('dpc', 'I', 0),
        ('si', 'B', PD_SI_MGMT),
        ('ni', 'B', PD_NI_INTERNATINAL),
        ('mp', 'B', 0),
        ('sls', 'B', 0),
    )
    __hdr__ = M3UAParam.__hdr__ + __hdr_spec__


# Dictionary to call appropriate subclass from superclass.
# TODO: Implement other subclasses and add them.
PARAM_TYPES_DICT = {
    M3UA_PROTOCOL_DATA: ParamProtocolData,
}


# list of Common Header, Network Appearance and Protocol Data.
# Protocol Data includes dummy value in it to test padding feature.
__payloads = [
    b'\x01\x00\x01\x01\x00\x00\x00\x24',
    b'\x02\x00\x00\x08\x00\x00\x00\x01',
    b'\x02\x10\x00\x13\x00\x00\xff\xff\x00\x00\xff\xfe\x03\x00\x00\x01\xc0\xff\xee\x00'
]
__s = b''.join(__payloads)


def test_pack():
    """Packing test.
    Create M3UA/M3UAParam instance by inserting values to the fields
    manually, then check if the values are expectedly set and the
    payload as a whole is the same as the bytearray above.
    """

    m3ua = M3UA(ver=1, rsv=0, cls=1, type=1)
    paramlist = [
        M3UAParam(tag=M3UA_NETWORK_APPEARANCE),
        M3UAParam(tag=M3UA_PROTOCOL_DATA)
    ]
    paramlist[0].data = b'\x00\x00\x00\x01'
    paramlist[1].data = b'\x00\x00\xff\xff\x00\x00\xff\xfe\x03\x00\x00\x01\xc0\xff\xee'
    m3ua.data = [bytes(x) for x in paramlist]

    assert (bytes(m3ua) == __s)


def test_unpack():
    m3ua = M3UA(__s)
    assert (m3ua.ver == 1)
    assert (m3ua.rsv == 0)
    assert (m3ua.cls == 1)
    assert (m3ua.type == 1)
    assert (m3ua.len == 36)

    param = m3ua.data

    for i in range(len(m3ua.params)):
        param = m3ua.params[i]
        if param.tag == M3UA_NETWORK_APPEARANCE:
            assert (param.len == 8)
            assert (len(param) == 8)
            assert (param.value == b'\x00\x00\x00\x01')
            assert (param.data == b'\x00\x00\x00\x01')
        if param.tag == M3UA_PROTOCOL_DATA:
            assert (param.len == 19)
            assert (len(param) == 20)
            assert (param.opc == 65535)
            assert (param.dpc == 65534)
            assert (param.si == PD_SI_SCCP)
            assert (param.ni == PD_NI_INTERNATINAL)
            assert (param.mp == 0)
            assert (param.sls == 1)
            assert (param.value == b'\xc0\xff\xee')
            assert (param.data == b'\xc0\xff\xee\x00')
