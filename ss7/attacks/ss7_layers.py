#!/usr/bin/env python
"""
SS7 Protocol Layers for Scapy
Includes M3UA, SCCP, and integration with TCAP/MAP layers.
"""
import os
import sys
from scapy.all import *
from scapy.fields import *
from scapy.packet import Packet

# Try to import TCAP/MAP layers
try:
    from .asn1_utils import *
    from .tcap_layer import *
    from .map_layer import *
    HAS_MAP = True
except ImportError:
    HAS_MAP = False

# ============================================
# UTILITY FUNCTIONS
# ============================================

def get_input(prompt, default=None, validator=None):
    """Get user input with optional default and validation."""
    if default:
        full_prompt = f"{prompt} [{default}]: "
    else:
        full_prompt = f"{prompt}: "
    
    while True:
        data = input(full_prompt)
        if not data and default:
            data = default
        
        if validator:
            if validator(data):
                return data
            else:
                print("Invalid input, please try again.")
        else:
            return data

def validate_ip(ip_str):
    """Validate an IP address."""
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

def validate_msisdn(msisdn):
    """Validate MSISDN (phone number)."""
    return msisdn.isdigit() and len(msisdn) >= 10

def validate_imsi(imsi):
    """Validate IMSI."""
    return imsi.isdigit() and 14 <= len(imsi) <= 15

# ============================================
# M3UA LAYER (MTP3 User Adaptation)
# ============================================

class M3UA(Packet):
    """M3UA Protocol Header."""
    name = "M3UA"
    fields_desc = [
        ByteField("version", 1),
        ByteField("reserved", 0),
        ByteEnumField("msg_class", 1, {
            0: "MGMT",
            1: "Transfer",
            2: "SSNM",
            3: "ASPSM",
            4: "ASPTM",
            9: "RKM"
        }),
        ByteEnumField("msg_type", 1, {
            1: "DATA",
            2: "DUNA",
            3: "DAVA",
            4: "DAUD",
            5: "SCON",
            6: "DUPU"
        }),
        IntField("length", None)
    ]
    
    def post_build(self, pkt, pay):
        if self.length is None:
            total_len = len(pkt) + len(pay)
            pkt = pkt[:4] + struct.pack(">I", total_len) + pkt[8:]
        return pkt + pay

class M3UA_Param_Protocol_Data(Packet):
    """M3UA Protocol Data Parameter."""
    name = "M3UA_Protocol_Data"
    fields_desc = [
        ShortField("tag", 0x0210),  # Protocol Data tag
        ShortField("length", None),
        IntField("opc", 0),         # Originating Point Code
        IntField("dpc", 0),         # Destination Point Code
        ByteField("si", 3),         # Service Indicator (3 = SCCP)
        ByteField("ni", 2),         # Network Indicator
        ByteField("mp", 0),         # Message Priority
        ByteField("sls", 0)         # Signaling Link Selection
    ]
    
    def post_build(self, pkt, pay):
        if self.length is None:
            total_len = len(pkt) + len(pay)
            pkt = pkt[:2] + struct.pack(">H", total_len) + pkt[4:]
        return pkt + pay

# ============================================
# SCCP LAYER (Signaling Connection Control Part)
# ============================================

class SCCP_UDT(Packet):
    """SCCP Unitdata (UDT) Message."""
    name = "SCCP_UDT"
    fields_desc = [
        ByteField("msg_type", 0x09),      # UDT
        ByteField("protocol_class", 0x00), # Class 0
        ByteField("pointer_called", 3),
        ByteField("pointer_calling", None),
        ByteField("pointer_data", None)
    ]

class SCCP_Address(Packet):
    """SCCP Address (Called/Calling Party)."""
    name = "SCCP_Address"
    fields_desc = [
        ByteField("length", None),
        ByteField("address_indicator", 0x12),
        ByteField("ssn", 6),  # SSN 6 = HLR, 7 = VLR, 8 = MSC
        # Global Title follows
    ]

SCCPUDT = SCCP_UDT  # Alias

# SSN Constants for easy reference
SSN_HLR = 6
SSN_VLR = 7
SSN_MSC = 8
SSN_EIR = 9
SSN_AUC = 10
SSN_GMLC = 145
SSN_CAP = 146
SSN_gsmSCF = 147
SSN_SGSN = 149
SSN_GGSN = 150

def build_sccp_called_address(gt_digits, ssn=SSN_HLR):
    """
    Build SCCP Called Party Address with Global Title.
    
    Args:
        gt_digits: Global Title digits (e.g., "905551234567")
        ssn: Subsystem Number (6=HLR, 7=VLR, 8=MSC)
    
    Returns:
        bytes: Encoded SCCP address
    """
    # Address Indicator:
    # bit 0: PC indicator (0 = no PC)
    # bit 1: SSN indicator (1 = SSN included)
    # bits 2-5: GT indicator (0100 = GT includes TT, NP, ES, NAI)
    # bits 6-7: Routing indicator (00 = route on GT)
    ai = 0x12  # SSN present, GT type 0100, route on GT
    
    # Global Title: Translation Type + Numbering Plan + Encoding Scheme + Nature
    tt = 0x00           # Translation Type: 0
    np_es = 0x12        # Numbering Plan: ISDN (1), Encoding: BCD even (2)
    nai = 0x04          # Nature: International
    
    # Encode GT digits as BCD
    gt_bcd = _encode_gt_bcd(gt_digits)
    
    addr = bytes([ai, ssn, tt, np_es, nai]) + gt_bcd
    return bytes([len(addr)]) + addr

def build_sccp_calling_address(gt_digits, ssn=SSN_HLR):
    """Build SCCP Calling Party Address with Global Title."""
    ai = 0x12
    tt = 0x00
    np_es = 0x12
    nai = 0x04
    
    gt_bcd = _encode_gt_bcd(gt_digits)
    addr = bytes([ai, ssn, tt, np_es, nai]) + gt_bcd
    return bytes([len(addr)]) + addr

def _encode_gt_bcd(digits):
    """Encode GT digits to BCD format."""
    result = []
    if len(digits) % 2 == 1:
        digits += '0'
    for i in range(0, len(digits), 2):
        low = int(digits[i])
        high = int(digits[i+1])
        result.append((high << 4) | low)
    return bytes(result)

def build_sccp_udt(called_addr, calling_addr, data):
    """
    Build a complete SCCP UDT message with addresses and data.
    
    Args:
        called_addr: Called party address bytes
        calling_addr: Calling party address bytes  
        data: TCAP/MAP payload bytes
        
    Returns:
        bytes: Complete SCCP UDT message
    """
    msg_type = 0x09      # UDT
    proto_class = 0x00   # Class 0, no special options
    
    # Calculate pointers
    ptr_called = 3       # Points to called address (relative to pointer position)
    ptr_calling = ptr_called + len(called_addr)
    ptr_data = ptr_calling + len(calling_addr)
    
    # Build message
    sccp = bytes([msg_type, proto_class, ptr_called, ptr_calling, ptr_data])
    sccp += called_addr
    sccp += calling_addr
    sccp += bytes([len(data)]) + data
    
    return sccp

# ============================================
# PACKET BINDING
# ============================================

bind_layers(M3UA, M3UA_Param_Protocol_Data)

# ============================================
# HELPER FUNCTIONS FOR ATTACK MODULES
# ============================================

def build_ss7_packet(local_ip, local_port, remote_ip, remote_port, 
                     opc, dpc, map_message):
    """
    Build a complete SS7 packet with all layers.
    
    Args:
        local_ip: Local IP address
        local_port: Local SCTP port
        remote_ip: Remote IP address  
        remote_port: Remote SCTP port
        opc: Originating Point Code
        dpc: Destination Point Code
        map_message: MAPMessage instance
    
    Returns:
        Scapy packet ready to send
    """
    # IP Layer
    ip = IP(src=local_ip, dst=remote_ip)
    
    # SCTP Layer
    sctp = SCTP(sport=local_port, dport=remote_port)
    sctp_data = SCTPChunkData(data=b'')  # Will be replaced
    
    # M3UA Layer
    m3ua = M3UA(msg_class=1, msg_type=1)
    proto_data = M3UA_Param_Protocol_Data(opc=opc, dpc=dpc, si=3, ni=2)
    
    # TCAP/MAP Layer
    if HAS_MAP and isinstance(map_message, MAPMessage):
        tcap_data = map_message.to_tcap_begin()
    else:
        tcap_data = b''
    
    # Build complete packet
    packet = ip / sctp / m3ua / proto_data / Raw(load=tcap_data)
    
    return packet

def parse_map_response(data):
    """
    Parse a MAP response from raw data.
    
    Returns:
        dict with parsed response fields
    """
    result = {
        'success': False,
        'imsi': None,
        'msisdn': None,
        'msc': None,
        'vlr': None,
        'lac': None,
        'cell_id': None,
        'error': None
    }
    
    if not data or len(data) < 10:
        result['error'] = "No data or too short"
        return result
    
    # Try to decode TCAP
    if HAS_MAP:
        try:
            tcap = decode_tcap(data)
            if tcap['type'] in [TCAP_END, TCAP_CONTINUE]:
                result['success'] = True
                # Parse components for actual data
                # This would need more detailed parsing
        except Exception as e:
            result['error'] = str(e)
    
    return result
