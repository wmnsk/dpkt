# -*- coding: utf-8 -*-
"""Signaling System No.7 - Signalling Connection Control Part"""

from __future__ import absolute_import
from __future__ import print_function

import struct

from . import dpkt
from .compat import compat_ord

# for debugging
from binascii import hexlify as hx


# SCCP Message Types
TYPE_CR = 1
TYPE_CC = 2
TYPE_CREF = 3 
TYPE_RLSD = 4
TYPE_RLC = 5
TYPE_DT1 = 6
TYPE_DT2 = 7
TYPE_AK = 8
TYPE_UDT = 9
TYPE_UDTS = 10
TYPE_ED = 11
TYPE_EA = 12
TYPE_RSR = 13
TYPE_RSC = 14
TYPE_ERR = 15
TYPE_IT = 16
TYPE_XUDT = 17
TYPE_XUDTS = 18
TYPE_LUDT = 19
TYPE_LUDTS = 20

# Message Handlings
MH_NO_SPECIAL_OPTIONS = 0
MH_RETURN_MSG_ON_ERROR = 8

# Subsystem Numbers
SSN_UNKNOWN = 0
SSN_SCCP_MGMT = 1
SSN_ISUP = 3
SSN_OMAP = 4
SSN_MAP = 5
SSN_HLR = 6
SSN_VLR = 7
SSN_MSC = 8
SSN_EIR = 9
SSN_AUC = 10
SSN_ISDN_SS = 11
SSN_BISDNE2EAPP = 13
SSN_TCTR = 14
SSN_RANAP = 142
SSN_RNSAP = 143
SSN_GMLC = 145
SSN_CAP = 146
SSN_GSM_SCF = 147
SSN_SIWF = 148
SSN_SGSN = 149
SSN_GGSN = 150
SSN_PCAP = 249
SSN_BSC_BSSAP = 250
SSN_MSC_BSSAP = 251
SSN_SMLC_BSSAP = 252
SSN_BSSOM = 253
SSN_BSSAP = 254


# Global Title Indicators
GTI_NO_GT = 0
GTI_NAI_ONLY = 1
GTI_TT_ONLY = 2
GTI_TT_NPI_ES = 3
GTI_TT_NPI_ES_NAI = 4

# NPI
NPI_UNKNOWN = 0
NPI_ISDN_TELEPHONY = 1
NPI_GENERIC = 2
NPI_DATA = 3
NPI_TELEX = 4
NPI_MARITIME_MOBILE = 5
NPI_LAND_MOBILE = 6
NPI_ISDN_MOBILE = 7
NPI_PRIVATE = 14

# ES
ES_UNKNOWN = 0
ES_BCD_ODD = 1
ES_BCD_EVEN = 2
ES_NATIONAL_SPARE = 3

# NAI
NAI_UNKNOWN = 0
NAI_SUBSCRIBER_NUMBER = 1
NAI_RSV_NATIONAL = 2
NAI_NATIONAL_SIGNIFICANT = 3
NAI_INTERNATIONAL_NUMBER = 4


class SCCP(dpkt.Packet):
    """Generic SCCP Header.
    TODO: more docstring

    Attributes:
        __hdr__: Generic Header fields of SCCP.
                  - type : SCCP Message Type
                  - flags: flags consists of message handling and class.
    """
    __hdr__ = (
        ('type', 'B', TYPE_CR),
        ('flags', 's', 0),
    )

    @property
    def msg_handling(self):
        return (self.flags >> 4) & 0xf

    @msg_handling.setter
    def msg_handling(self, m):
        self.flags = (self.flags & ~0xf0) | ((m & 0xf) << 4)

    @property
    def cls(self):
        return self.flags & 0xf

    @cls.setter
    def cls(self, c):
        self.flags = (self.flags & ~0xf) | (c & 0xf)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)

        self.len = len(self.data) + self.__hdr_len__
        self.flags = compat_ord(self.flags[0])
        self.data = self.data[:self.len - self.__hdr_len__]

        self.types = SCCP_TYPES_DICT.get(self.type, SCCPInvalidType)(self.data)

    def pack_hdr(self):
        self.flags = struct.pack('B', (self.flags) & 0xff)
        self.len = self.__hdr_len__ + len(self.data)

        return dpkt.Packet.pack_hdr(self)


class SCCPInvalidType(object):
    """SCCP Message Type Invalid or Unknown.
    TODO: more docstring
    
    """
    pass


class TypeUnitData(dpkt.Packet):
    """SCCP Message Type Unitdata(UDT).
       The UDT message contains:
        - three pointers;
        - the following parameters.
           - Calling Party Address
           - Called Party Address
           - Data (Upper Layers)

    Attributes:
        __hdr__: Basic UDT message headers.
                  - p1: Pointer to 1st mandatory variable parameter.
                  - p2: Pointer to 2nd mandatory variable parameter.
                  - p3: Pointer to 3rd mandatory variable parameter.
    """
    __hdr__ = (
        ('p1', 'B', 3),
        ('p2', 'B', 0),
        ('p3', 'B', 0),
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)

        self.cgpa = ParamPartyAddress(self.data[:self.p2 - self.p1 + 1])
        self.cdpa = ParamPartyAddress(self.data[self.p2 - self.p1 + 1:self.p3 - self.p1 + 2])
        self.upper_layers = self.data[self.p3 - 1:]
        self.data = [self.cgpa, self.cdpa, self.upper_layers]

    def pack_hdr(self):
        self.data = [bytes(d) for d in self.data]
        self.p3 = sum(map(len, self.data[:2])) + 1
        self.p2 = len(self.data[0]) + 2
        self.p1 = 3

        return dpkt.Packet.pack_hdr(self)

    def __len__(self):
        return self.__hdr_len__ + sum(map(len, self.data))

    def __bytes__(self):
        return self.pack_hdr() + b''.join(map(bytes, self.data))


class ParamPartyAddress(dpkt.Packet):
    """SCCP Mandatory Variable Parameter.
    TODO: more docstring
    
    Attributes:
        __hdr__: 
    """
    __hdr__ = (
       ('len', 'B', 0),
       ('indicators', 's', 0)
    )

    @property
    def pc_indicator(self):
        return self.indicators & 0x1

    @pc_indicator.setter
    def pc_indicator(self, p):
        self.indicators = (self.indicators & ~0x1) | (p & 0x1)

    @property
    def ssn_indicator(self):
        return (self.indicators >> 1) & 0x1

    @ssn_indicator.setter
    def ssn_indicator(self, s):
        self.indicators = (self.indicators & ~0x2) | ((s & 0x1) << 1)

    @property
    def gt_indicator(self):
        return (self.indicators >> 2) & 0xf

    @gt_indicator.setter
    def gt_indicator(self, g):
        self.indicators = (self.indicators & ~0x3c) | ((g & 0xf) << 2)

    @property
    def routing_indicator(self):
        return (self.indicators >> 6) & 0x1

    @routing_indicator.setter
    def routing_indicator(self, r):
        self.indicators = (self.indicators & ~0x40) | ((r & 0x1) << 6)

    @property
    def rsv_bit(self):
        return (self.indicators >> 7) & 0x1

    @rsv_bit.setter
    def rsv_bit(self, r):
        self.indicators = (self.indicators & ~0x80) | ((r & 0x1) << 7)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)

        self.indicators = compat_ord(self.indicators[0])
        if self.pc_indicator:
            self.pc = self.data[:2]
            self.data = self.data[2:]

        if self.ssn_indicator:
            self.ssn = compat_ord(self.data[:1])
            self.data = self.data[1:]

        if self.gt_indicator:
            self.gt = GlobalTitle(self.data)
            self.data = self.data[len(self.gt):]

    def pack_hdr(self):
        if self.pc_indicator:
            self.data += struct.pack('B', self.pc)

        if self.ssn_indicator:
            self.data += struct.pack('B', self.ssn)

        if self.gt_indicator:
            self.data += bytes(self.gt)

        self.indicators = struct.pack('B', (self.indicators) & 0xff)
        self.len = self.__hdr_len__ + len(bytes(self.data)) - 1

        return dpkt.Packet.pack_hdr(self)


class GlobalTitle(dpkt.Packet):
    """Global Title(GT)
    TODO: more docstring

    Attributes:
        __hdr__: 
    """
    __hdr__ = (
        ('tt', 'B', 0),
        ('flags', 'H', 0),
    )

    @property
    def npi(self):
        return (self.flags >> 12) & 0xf

    @npi.setter
    def npi(self, n):
        self.flags = (self.flags & ~0xf000) | ((n & 0xf) << 12)

    @property
    def es(self):
        return (self.flags >> 8) & 0xf

    @es.setter
    def es(self, e):
        self.flags = (self.flags & ~0xf00) | ((e & 0xf) << 8)

    @property
    def nai(self):
        return self.flags & 0xff

    @nai.setter
    def nai(self, n):
        self.flags = (self.flags & ~0xff) | (n & 0xff)

    def swap4bits(self, octet):
        return ((octet & 0xf) << 4) ^ ((octet >> 4) & 0xf)

    @property
    def digits(self):
        swp = lambda s: self.swap4bits(compat_ord(s))
        fmt = lambda s: '{0:0>2x}'.format(s).encode('utf-8')
        return b''.join([fmt(swp(s)) for s in self.data])[:-1]

    @digits.setter
    def digits(self, d):
        d = d + '0'
        l = [self.swap4bits(s) for s in bytearray.fromhex(d)]
        self._dg = b''.join([struct.pack('B', i) for i in l])

    def pack_hdr(self):
        self.data = self._dg + self.data
        return dpkt.Packet.pack_hdr(self)


SCCP_TYPES_DICT = {
    TYPE_UDT: TypeUnitData,
    }

'''
SCCP_TYPES_DICT = {
    TYPE_CR: TypeConnRequest,
    TYPE_CC: TypeConnConfirm,
    TYPE_CREF: TypeConnRefused,
    TYPE_RLSD: TypeReleased,
    TYPE_RLC: TypeReleaseComplete,
    TYPE_DT1: TypeDataForm1,
    TYPE_DT2: TypeDataForm2,
    TYPE_AK: TypeAcknowlegement
    TYPE_UDT: TypeUnitData,
    TYPE_UDTS: TypeUnitDataService
    TYPE_ED: TypeExpeditedData
    TYPE_EA: TypeExpeditedDataAck
    TYPE_RSR: TypeResetRequest
    TYPE_RSR: TypeResetConfirm
    TYPE_ERR: TypePDUError
    TYPE_IT: TypeInactivityTest
    TYPE_XUDT: TypeExtUnitData
    TYPE_XUDTS: TypeExtUnitDataService
    TYPE_LUDT: TypeLongUnitData
    TYPE_LUDTS: TypeLongUnitDataService
}

'''

__payloads = [
    b'\t\x80\x03\r\x17',
    b'\n\x12\x06\x00\x11\x04\x89gE#\x01',
    b'\n\x12\x08\x00\x11\x04!Ce\x87\t',
    b'\xde\xad\xbe\xef'
]

__sccp = b''.join(__payloads)


def test_unpack():
    s = SCCP(__sccp)
    assert s.type == TYPE_UDT
    assert s.cls == 0
    assert s.msg_handling == MH_RETURN_MSG_ON_ERROR

    udt = TypeUnitData(s.data)
    for u in udt.data:
        if isinstance(u, ParamPartyAddress):
            assert (u.pc_indicator == 0)
            assert (u.ssn_indicator == 1)
            assert (u.gt_indicator == GTI_TT_NPI_ES_NAI)
            assert (u.routing_indicator == 0)
            assert (u.rsv_bit == 0)
            if isinstance(u.gt, GlobalTitle):
                gt = u.gt
                assert (gt.tt == 0)
                assert (gt.npi == NPI_ISDN_TELEPHONY)
                assert (gt.es == ES_BCD_ODD)
                assert (gt.nai == NAI_INTERNATIONAL_NUMBER)
                assert (gt.digits == b'987654321' or b'123456789')
        else:
            assert (u == b'\xde\xad\xbe\xef')

    assert (bytes(s) == __sccp)


def test_pack():
    s = SCCP(
        type=TYPE_UDT,
        msg_handling=MH_RETURN_MSG_ON_ERROR,
        cls=0
        )

    params = [
        ParamPartyAddress(
            pc_indicator=0,
            ssn_indicator=1,
            gt_indicator=GTI_TT_NPI_ES_NAI,
            routing_indicator=0,
            rsv_bit=0,
            ssn=6,
            gt=GlobalTitle(
                npi=NPI_ISDN_TELEPHONY,
                es=ES_BCD_ODD,
                nai=NAI_INTERNATIONAL_NUMBER,
                digits='987654321'
            )
        ),
        ParamPartyAddress(
            pc_indicator=0,
            ssn_indicator=1,
            gt_indicator=GTI_TT_NPI_ES_NAI,
            routing_indicator=0,
            rsv_bit=0,
            ssn=8,
            gt=GlobalTitle(
                npi=NPI_ISDN_TELEPHONY,
                es=ES_BCD_ODD,
                nai=NAI_INTERNATIONAL_NUMBER,
                digits='123456789'
            )
        ),
        b'\xde\xad\xbe\xef'
    ]

    udt = TypeUnitData(data=params)
    s.data = udt
    assert (bytes(s) == __sccp)
