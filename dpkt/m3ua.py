# -*- coding: utf-8 -*-
"""MTP3-User Adaptation Layer (M3UA)"""

from __future__ import print_function
from __future__ import absolute_import

import struct

from . import dpkt


# Signaling System 7 (SS7) Message Transfer Part 3 (MTP3)
# User Adaptation Layer (M3UA) - rfc4688
# https://tools.ietf.org/html/rfc4688


# M3UA Parameter Tags
PRM_INFO_STRING = 4
PRM_ROUTING_CXT = 6
PRM_DIAG_INFO = 7
PRM_HEARTBEAT_DATA = 9
PRM_TFC_MODE_TYPE = 11
PRM_ERROR_CODE = 12
PRM_STATUS = 13
PRM_ASP_ID = 17
PRM_AFFECTED_PC = 18
PRM_CORRELATION_ID = 19
PRM_NETWORK_APPEARANCE = 512
PRM_USER_CAUSE = 516
PRM_CONG_INDICATIONS = 517
PRM_CONCERNED_DST = 518
PRM_ROUTING_KEY = 519
PRM_REGIST_RESULT = 520
PRM_DEREGIST_RESULT = 521
PRM_LOCAL_RK_ID = 522
PRM_DST_PC = 523
PRM_SERVICE_INDICATORS = 524
PRM_ORG_PC_LIST = 526
PRM_PROTOCOL_DATA = 528
PRM_REGIST_STATUS = 530
PRM_DEREGIST_STATUS = 531

# M3UA Errors
ERR_INV_VERSION = 1
ERR_USP_MSG_CLASS = 3
ERR_USP_MSG_TYPE = 4
ERR_USP_TFC_MODE_TYPE = 5
ERR_UNEXPECTED_MESSAGE = 6
ERR_PROTOCOL_ERROR = 7
ERR_INV_STREAM_IDENTIFIER = 9
ERR_REFUSED_MANAGEMENT_BLOCKING = 13
ERR_ASP_IDENTIFIER_REQUIRED = 14
ERR_INV_ASP_IDENTIFIER = 15
ERR_INV_PARAMETER_VALUE = 17
ERR_PARAMETER_FIELD_ERROR = 18
ERR_UNEXPECTED_PARAMETER = 19
ERR_DESTINATION_STATUS_UNKNOWN = 20
ERR_INV_NETWORK_APPEARANCE = 21
ERR_MISSING_PARAMETER = 22
ERR_INV_RC = 25
ERR_NO_CONFIGURED_AS_FOR_ASP = 26

# M3UA Status Types
STATUS_TYPE_AS_CHANGE = 1
STATUS_TYPE_OTHER = 2

# M3UA Status Information
STATUS_INFO_RESERVED = 1
STATUS_INFO_AS_INACTIVE = 2
STATUS_INFO_AS_ACTIVE = 3
STATUS_INFO_AS_PENDING = 4

# M3UA Unavailability Causes
CAUSE_UNKNOWN = 1
CAUSE_UNEQUIPPED = 2
CAUSE_INACCESSIBLE = 3

# M3UA User Identities
USER_SCCP = 3
USER_TUP = 4
USER_ISUP = 5
USER_BB_ISUP = 9
USER_SATEL_ISUP = 10
USER_AAL_TYPE2_SIG = 12
USER_BICC = 13
USER_GCP = 14

# M3UA Registration Status
REG_SUCCESS_REG = 0
REG_ERR_UNKNWON = 1
REG_ERR_INV_DPC = 2
REG_ERR_INV_NA = 3
REG_ERR_INV_RK = 4
REG_ERR_PERMISSION_DENIED = 5
REG_ERR_CANNOT_SUPPORT_UNIQ_ROUTING = 6
REG_ERR_RK_NOT_CURR_PROVISIONED = 7
REG_ERR_INSUFFICIENT_RESOURCES = 8
REG_ERR_USP_RK_PRM_FIELD = 9
REG_ERR_USP_INV_TFC_HANDLING_MODE = 10
REG_ERR_RK_CHANGE_REFUSED = 11
REG_ERR_RK_ALREADY_REG = 12

# M3UA Deregistration Status
DEREG_SUCCESS_DEREG = 0
DEREG_ERR_UNKNOWN = 1
DEREG_ERR_INV_RC = 2
DEREG_ERR_PERMISSION_DENIED = 3
DEREG_ERR_NOT_REG = 4
DEREG_ERR_ASP_CURR_ACTIVE_FOR_RC = 5

# M3UA Network Indicators for Protocol Data
PD_NI_INTERNATINAL = 0
PD_NI_NATIONAL = 2
PD_NI_RSV_NATIONAL = 3

# M3UA Service Indicators for Protocol Data
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
            param = PRM_TYPES_DICT.get(ptype, M3UAParam)(self.data)
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


class ParamInfoString(M3UAParam):
    """M3UA INFO String parameter.
    This field doesn't have the parameter-specific header,
    used just to carry informational message string in utf-8.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
    """
    __hdr__ = M3UAParam.__hdr__

    def pack_hdr(self):
        self.tag = PRM_INFO_STRING
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamRoutingContext(M3UAParam):
    """M3UA Routing Context parameter.
    This field doesn't have the parameter-specific header,
    the length of the data depends on the type of message.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
    """
    __hdr__ = M3UAParam.__hdr__

    def pack_hdr(self):
        self.tag = PRM_ROUTING_CXT
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamDiagnosticInfo(M3UAParam):
    """M3UA Diagnostic Info parameter.
    This field doesn't have the parameter-specific header,
    the length of the data depends on the type of message.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
    """
    __hdr__ = M3UAParam.__hdr__

    def pack_hdr(self):
        self.tag = PRM_DIAG_INFO
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamHeartbeatData(M3UAParam):
    """M3UA Heartbeat Data parameter.
    This field doesn't have the parameter-specific header,
    the length of the data depends on the type of message.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
    """
    __hdr__ = M3UAParam.__hdr__

    def pack_hdr(self):
        self.tag = PRM_HEARTBEAT_DATA
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamTrafficModeType(M3UAParam):
    """M3UA Traffic Mode Type parameter.
    This field doesn't have the parameter-specific header,
    but the data field is always the same in length.
    If the length of this parameter is longer than 32 bits,
    it indicates there's something wrong in protocol format.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
        __hdr_spec__: Parameter-specific fields of M3UA.
    """
    __hdr_spec__ = (
        ('traffic_mode_type', 'I', 0),
    )
    __hdr__ = M3UAParam.__hdr__ + __hdr_spec__

    def pack_hdr(self):
        self.tag = PRM_TFC_MODE_TYPE
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamErrorCode(M3UAParam):
    """M3UA Error Code parameter.
    This field doesn't have the parameter-specific header,
    but the data field is always the same in length.
    If the length of this parameter is longer than 32 bits,
    it indicates there's something wrong in protocol format.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
        __hdr_spec__: Parameter-specific fields of M3UA.
    """
    __hdr_spec__ = (
        ('err_code', 'I', ERR_INV_VERSION),
    )
    __hdr__ = M3UAParam.__hdr__ + __hdr_spec__

    def pack_hdr(self):
        self.tag = PRM_ERROR_CODE
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamStatus(M3UAParam):
    """M3UA Status parameter.
    This parameter is used when sending Notify message.
    Supported fields are;
     - Status Type
     - Status Information

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
        __hdr_spec__: Parameter-specific fields of M3UA.
    """
    __hdr_spec__ = (
        ('status_type', 'H', STATUS_TYPE_AS_CHANGE),
        ('status_info', 'H', STATUS_INFO_AS_INACTIVE),
    )
    __hdr__ = M3UAParam.__hdr__ + __hdr_spec__

    def pack_hdr(self):
        self.tag = PRM_STATUS
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamAspIdentifier(M3UAParam):
    """M3UA ASP Identifier parameter.
    This field doesn't have the parameter-specific header,
    but the data field is always the same in length.
    If the length of this parameter is longer than 32 bits,
    it indicates there's something wrong in protocol format.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
        __hdr_spec__: Parameter-specific fields of M3UA.
    """
    __hdr_spec__ = (
        ('asp_id', 'I', 0),
    )
    __hdr__ = M3UAParam.__hdr__ + __hdr_spec__

    def pack_hdr(self):
        self.tag = PRM_ASP_ID
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamAffectedPointCode(M3UAParam):
    """M3UA Affected Point Code parameter.
    This parameter has the list of affected PCs and
    masks to identify a contiguous range of affected PCs.

    TODO: Need to implement packing/unpacking for multiple values.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
        __hdr_spec__: Parameter-specific fields of M3UA.
    """
    __hdr__ = M3UAParam.__hdr__

    def pack_hdr(self):
        self.tag = PRM_AFFECTED_PC
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamCorrelationId(M3UAParam):
    """M3UA Correlation Id parameter.
    This field doesn't have the parameter-specific header,
    but the data field is always the same in length.
    If the length of this parameter is longer than 32 bits,
    it indicates there's something wrong in protocol format.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
        __hdr_spec__: Parameter-specific fields of M3UA.
    """
    __hdr_spec__ = (
        ('corr_id', 'I', 0),
    )
    __hdr__ = M3UAParam.__hdr__ + __hdr_spec__

    def pack_hdr(self):
        self.tag = PRM_CORRELATION_ID
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamNetworkAppearance(M3UAParam):
    """M3UA Network Appearance parameter.
    This field doesn't have the parameter-specific header,
    but the data field is always the same in length.
    If the length of this parameter is longer than 32 bits,
    it indicates there's something wrong in protocol format.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
        __hdr_spec__: Parameter-specific fields of M3UA.
    """
    __hdr_spec__ = (
        ('nw_appearance', 'I', 0),
    )
    __hdr__ = M3UAParam.__hdr__ + __hdr_spec__

    def pack_hdr(self):
        self.tag = PRM_NETWORK_APPEARANCE
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamUserCause(M3UAParam):
    """M3UA User/Cause parameter.
    This field doesn't have the parameter-specific header,
    but the data field is always the same in length.
    If the length of this parameter is longer than 32 bits,
    it indicates there's something wrong in protocol format.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
        __hdr_spec__: Parameter-specific fields of M3UA.
    """
    __hdr_spec__ = (
        ('cause', 'H', CAUSE_UNEQUIPPED),
        ('user', 'H', USER_SCCP),
    )
    __hdr__ = M3UAParam.__hdr__ + __hdr_spec__

    def pack_hdr(self):
        self.tag = PRM_USER_CAUSE
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamCongestionIndications(M3UAParam):
    """M3UA Congestion Indications parameter.
    This field doesn't have the parameter-specific header,
    but the data field is always the same in length.
    If the length of this parameter is longer than 32 bits,
    it indicates there's something wrong in protocol format.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
        __hdr_spec__: Parameter-specific fields of M3UA.
    """
    __hdr_spec__ = (
        ('cong_indications', 'I', 0),
    )
    __hdr__ = M3UAParam.__hdr__ + __hdr_spec__

    def pack_hdr(self):
        self.tag = PRM_CONG_INDICATIONS
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamConcernedDestination(M3UAParam):
    """M3UA Concerned Destination parameter.
    This parameter is only used if SCON message is sent from
    an ASP to the SGP. It contains the point code of the
    originator of the message that triggered the SCON message.
    Supported fields are;
     - Reserved: This field is always filled with 0.
     - Concerned DPC: Destination Point Code that concerned

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
        __hdr_spec__: Parameter-specific fields of M3UA.

    TODO: Implement packing and unpacking for '3s'.
    """
    __hdr_spec__ = (
        ('cd_rsv', 'B', 0),
        ('concerned_dpc', '3s', 0),
    )
    __hdr__ = M3UAParam.__hdr__ + __hdr_spec__

    def pack_hdr(self):
        self.tag = PRM_CONCERNED_DST
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamRoutingKey(M3UAParam):
    """M3UA Local Routing Key Identifier parameter.
    This field doesn't have the parameter-specific header,
    the length of the data depends on the type of message.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
    """
    __hdr__ = M3UAParam.__hdr__

    def pack_hdr(self):
        self.tag = PRM_ROUTING_KEY
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamRegistrationResult(M3UAParam):
    """M3UA Registration Result parameter.
    This field doesn't have the parameter-specific header,
    the length of the data depends on the type of message.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
    """
    __hdr__ = M3UAParam.__hdr__

    def pack_hdr(self):
        self.tag = PRM_REGIST_RESULT
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamDeregistrationResult(M3UAParam):
    """M3UA Deregistration Result parameter.
    This field doesn't have the parameter-specific header,
    the length of the data depends on the type of message.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
    """
    __hdr__ = M3UAParam.__hdr__

    def pack_hdr(self):
        self.tag = PRM_DEREGIST_RESULT
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamLocalRKIdentifier(M3UAParam):
    """M3UA Local Routing Key Identifier parameter.
    This field doesn't have the parameter-specific header,
    but the data field is always the same in length.
    If the length of this parameter is longer than 32 bits,
    it indicates there's something wrong in protocol format.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
        __hdr_spec__: Parameter-specific fields of M3UA.
    """
    __hdr_spec__ = (
        ('local_rk_id', 'I', 0),
    )
    __hdr__ = M3UAParam.__hdr__ + __hdr_spec__

    def pack_hdr(self):
        self.tag = PRM_LOCAL_RK_ID
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamDestinationPointCode(M3UAParam):
    """M3UA Destination Point Code parameter.
    This parameter identifies the Destination Point Code of
    incoming SS7 traffic.
    Supported fields are;
     - mask: This field is always filled with 0.
     - dpc: Destination Point Code in digit format.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
        __hdr_spec__: Parameter-specific fields of M3UA.

    TODO: Implement packing/unpacking for '3s'.
    """
    __hdr_spec__ = (
        ('mask', 'B', 0),
        ('dpc', '3s', 0),
    )
    __hdr__ = M3UAParam.__hdr__ + __hdr_spec__

    def pack_hdr(self):
        self.tag = PRM_DST_PC
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamServiceIndicators(M3UAParam):
    """M3UA Service Indicators parameter.
    This parameter has the set of Service Indicators.
    If the number of SIs is not multiple of four, this parameter
    should be padded out to 32-byte alignment.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
        __hdr_spec__: Parameter-specific fields of M3UA.

    TODO: Implement si class with padding support.
    """
    __hdr__ = M3UAParam.__hdr__

    def pack_hdr(self):
        self.tag = PRM_SERVICE_INDICATORS
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamOriginatingPointCodeList(M3UAParam):
    """M3UA Originating Point Code List parameter.
    This parameter has the list of affected PCs and
    masks to identify a contiguous range of affected PCs.

    TODO: Need to implement packing/unpacking for multiple values.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
        __hdr_spec__: Parameter-specific fields of M3UA.
    """
    __hdr__ = M3UAParam.__hdr__

    def pack_hdr(self):
        self.tag = PRM_ORG_PC_LIST
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

    def pack_hdr(self):
        self.tag = PRM_PROTOCOL_DATA
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamRegistrationStatus(M3UAParam):
    """M3UA Registration Status parameter.
    This parameter indicates the registration result.
    This field doesn't have the parameter-specific header,
    but the data field is always the same in length.
    If the length of this parameter is longer than 32 bits,
    it indicates there's something wrong in protocol format.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
        __hdr_spec__: Parameter-specific fields of M3UA.
    """
    __hdr_spec__ = (
        ('reg_status', 'I', REG_SUCCESS_REG),
    )
    __hdr__ = M3UAParam.__hdr__ + __hdr_spec__

    def pack_hdr(self):
        self.tag = PRM_REGIST_STATUS
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


class ParamDeregistrationStatus(M3UAParam):
    """M3UA Deregistration Status parameter.
    This parameter indicates the deregistration result.
    This field doesn't have the parameter-specific header,
    but the data field is always the same in length.
    If the length of this parameter is longer than 32 bits,
    it indicates there's something wrong in protocol format.

    Attributes:
        __hdr__: Generic Parameter Header fields of M3UA.
        __hdr_spec__: Parameter-specific fields of M3UA.
    """
    __hdr_spec__ = (
        ('reg_status', 'I', DEREG_SUCCESS_DEREG),
    )
    __hdr__ = M3UAParam.__hdr__ + __hdr_spec__

    def pack_hdr(self):
        self.tag = PRM_DEREGIST_STATUS
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


# Dictionary to call appropriate subclass from superclass.
PRM_TYPES_DICT = {
    PRM_INFO_STRING: ParamInfoString,
    PRM_ROUTING_CXT: ParamRoutingContext,
    PRM_DIAG_INFO: ParamDiagnosticInfo,
    PRM_HEARTBEAT_DATA: ParamHeartbeatData,
    PRM_TFC_MODE_TYPE: ParamTrafficModeType,
    PRM_ERROR_CODE: ParamErrorCode,
    PRM_STATUS: ParamStatus,
    PRM_ASP_ID: ParamAspIdentifier,
    PRM_AFFECTED_PC: ParamAffectedPointCode,
    PRM_CORRELATION_ID: ParamCorrelationId,
    PRM_NETWORK_APPEARANCE: ParamNetworkAppearance,
    PRM_USER_CAUSE: ParamUserCause,
    PRM_CONG_INDICATIONS: ParamCongestionIndications,
    PRM_CONCERNED_DST: ParamConcernedDestination,
    PRM_ROUTING_KEY: ParamRoutingKey,
    PRM_REGIST_RESULT: ParamRegistrationResult,
    PRM_DEREGIST_RESULT: ParamDeregistrationResult,
    PRM_LOCAL_RK_ID: ParamLocalRKIdentifier,
    PRM_DST_PC: ParamDestinationPointCode,
    PRM_SERVICE_INDICATORS: ParamServiceIndicators,
    PRM_ORG_PC_LIST: ParamOriginatingPointCodeList,
    PRM_PROTOCOL_DATA: ParamProtocolData,
    PRM_REGIST_STATUS: ParamRegistrationStatus,
    PRM_DEREGIST_STATUS: ParamDeregistrationStatus
}


# list of Common Header, Network Appearance and Protocol Data.
# Protocol Data includes dummy value within it to test padding feature.
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

    TODO: Test all the parameters...
    """

    m3ua = M3UA(ver=1, rsv=0, cls=1, type=1)
    paramlist = [
        ParamNetworkAppearance(nw_appearance=1),
        ParamProtocolData(
            opc=65535,
            dpc=65534,
            si=PD_SI_SCCP,
            ni=PD_NI_INTERNATINAL,
            mp=0,
            sls=1
            )
        ]

    paramlist[0].data = b''
    paramlist[1].data = b'\xc0\xff\xee'
    m3ua.data = [bytes(x) for x in paramlist]

    assert (bytes(m3ua) == __s)


def test_unpack():
    """Unpacking test.
    Create MTP3 instance by loading the bytearray above and
    check if the values are expectedly decoded.

    TODO: Test all the parameters...
    """
    m3ua = M3UA(__s)
    assert (m3ua.ver == 1)
    assert (m3ua.rsv == 0)
    assert (m3ua.cls == 1)
    assert (m3ua.type == 1)
    assert (m3ua.len == 36)

    for i in range(len(m3ua.params)):
        param = m3ua.params[i]
        if param.tag == PRM_NETWORK_APPEARANCE:
            assert (param.len == 8)
            assert (len(param) == 8)
            assert (param.nw_appearance == 1)
            assert (param.data == b'')
        if param.tag == PRM_PROTOCOL_DATA:
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
