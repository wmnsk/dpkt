# -*- coding: utf-8 -*-
"""Signaling System No.7 - Signalling Connection Control Part"""

from __future__ import absolute_import
from __future__ import print_function

import struct

from . import dpkt
from .compat import compat_ord

from binascii import hexlify as hx


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

# Global Title Indicators
NO_GT = 0
NAI_ONLY = 1
TT_ONLY = 2
TT_NPI_ES = 3
TT_NPI_ES_NAI = 4

# NPI
NPI_ = 0

# ES
ES_ = 0

# NAI
NAI_ = 0


class SCCP(dpkt.Packet):
    """Generic SCCP Header.

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

        # param = SCCP_TYPES_DICT.get(self.type, SCCPInvalidType)(self.data)
        #     l.append(param)
        #     self.data = self.data[len(param):]

        self.types = SCCP_TYPES_DICT.get(self.type, SCCPInvalidType)(self.data)

    def pack_hdr(self):
        self.flags = struct.pack('B', (self.flags) & 0xff)
        self.len = self.__hdr_len__ + len(self.data)

        return dpkt.Packet.pack_hdr(self)


class SCCPInvalidType(object):
    """SCCP Message Type Invalid or Unknown.
    This class is used when the 'type' in SCCP class is
    not in the range 1-19.
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
        print('p1: %s' % self.p1)
        print('p2: %s' % self.p2)
        print('p3: %s' % self.p3)
        print('data: %s' % hx(self.data))

        # self.data = b''.join(self.data)
        self.cgpa = ParamPartyAddress(self.data[:self.p2 - self.p1 + 1])
        self.cdpa = ParamPartyAddress(self.data[self.p2 - self.p1 + 1:self.p3 - self.p1 + 2])
        self.upper_layers = self.data[self.p3 - 1:]
        self.data = [self.cgpa, self.cdpa, self.upper_layers]


        print('\n==================== CgPA ====================')
        print('cgpalen: %s' % self.cgpa.len)
        print('cgpaind: %s' % self.cgpa.indicators)
        print('cgpassn: %s' % self.cgpa.ssn)
        # print('cgpagt: %s' % hx(self.cgpa.gt))
        print('cgpadata: %s' % hx(self.cgpa.data))
        print('\n==================== CdPA ====================')
        print('cdpalen: %s' % self.cdpa.len)
        print('cdpaind: %s' % self.cdpa.indicators)
        print('cdpassn: %s' % self.cdpa.ssn)
        # print('cdpagt: %s' % hx(self.cdpa.gt))
        print('cdpadata: %s' % hx(self.cdpa.data))

        print('\n\ndata: %s' % self.data)


    def pack_hdr(self):
        self.data = [bytes(d) for d in self.data]
        self.p3 = sum(map(len, self.data[:2])) + 1
        self.p2 = len(self.data[0]) + 2
        self.p1 = 3
        print('pointers: %s %s %s' % (self.p1, self.p2, self.p3))
        print('data: %s' % self.data)
        # self.data = b''.join(bytes(self.data))
        # self.len = self.__hdr_len__ + len(self.data)

        return dpkt.Packet.pack_hdr(self)

    def __len__(self):
        return self.__hdr_len__ + sum(map(len, self.data))

    def __bytes__(self):
        return self.pack_hdr() + b''.join(map(bytes, self.data))


class ParamPartyAddress(dpkt.Packet):
    """SCCP Mandatory Variable Parameter.

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
        pass

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
    def gt_indicator(self, p):
        pass

    @property
    def routing_indicator(self):
        pass

    @routing_indicator.setter
    def routing_indicator(self, p):
        pass

    @property
    def rsv_bit(self):
        pass

    @rsv_bit.setter
    def rsv_bit(self, p):
        pass


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
    """
    __hdr__ = (
        ('tt', 'B', 0),
        ('flags', 'H', 0),
    )

    @property
    def npi(self):
        return (self.flags >> 12) & 0xf

    @npi.setter
    def npi(self, e):
        pass

    @property
    def es(self):
        return (self.flags >> 8) & 0xf

    @es.setter
    def es(self, e):
        pass

    @property
    def nai(self):
        return self.flags & 0xff

    @nai.setter
    def nai(self, e):
        pass

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

__s = b'\x09\x81\xde\xad\xbe\xef'
__t = b'\x09\x81\x03\xad\xbe\xef'

__payloads = [
    b'\t\x80\x03\r\x17',
    b'\n\x12\x06\x00\x11\x04\x89gE#\x01',
    b'\n\x12\x08\x00\x11\x04!Ce\x87\t',
    b'\xde\xad\xbe\xef'
]

__sccp = b''.join(__payloads)


def test_SCCP_base_unpack():
    s = SCCP(__sccp)

    assert s.type == TYPE_UDT
    assert s.cls == 0
    assert s.msg_handling == 8

    udt = TypeUnitData(s.data)
    for u in udt.data:
        if isinstance(u, ParamPartyAddress):
            print('UDT IND: %s' % u.indicators)
            print('UDT SSN: %s' % u.ssn)
            if isinstance(u.gt, GlobalTitle):
                gt = u.gt
                print('UDT GT TT: %s' % gt.tt)
                print('UDT GT FL: %s' % gt.flags)
                print('UDT GT NP: %s' % gt.npi)
                print('UDT GT ES: %s' % gt.es)
                print('UDT GT NA: %s' % gt.nai)
                print('UDT GT DG: %s' % gt.digits)
        else:
            print('UDT DATA: %s' % hx(u))

    assert (bytes(s) == __sccp)
    # assert (__sccp == 'hoge')


def test_SCCP_base_pack():
    print('================ PACKING ================')

    s = SCCP(
        type=TYPE_UDT,
        msg_handling=8,
        cls=0
        )

    params = [
        ParamPartyAddress(
            indicators=18,
            ssn=6,
            gt=GlobalTitle(
                flags=4356,
                digits='987654321'
            )
        ),
        ParamPartyAddress(
            indicators=18,
            ssn=8,
            gt=GlobalTitle(
                flags=4356,
                digits='123456789'
            )
        ),
        b'\xde\xad\xbe\xef'
    ]

    '''
    cgpa = ParamPartyAddress(
        pc_indicator=0,
        ssn_indicator=1,
        gt_indicator=TT_NPI_ES_NAI,
        routing_indicator=0,
        rsv_bit=0,
        ssn=6,
        gt=GlobalTitle(flags=4356, data='\x89gE#\x01')
        )

    cdpa = ParamPartyAddress(
        pc_indicator=0,
        ssn_indicator=1,
        gt_indicator=TT_NPI_ES_NAI,
        routing_indicator=0,
        rsv_bit=0,
        ssn=8,
        gt=GlobalTitle(flags=4356, data='!Ce\x87\t')
        )
    '''

    udt = TypeUnitData(data=params)
    s.data = udt
    assert (bytes(s) == __sccp)
    # assert (__sccp == 'hoge')
