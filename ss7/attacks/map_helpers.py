#!/usr/bin/env python
"""
MAP Protocol Helper Utilities
Common functions used across MAP attack modules.

This module re-exports the main MAP classes and provides
additional utility functions for SS7/MAP operations.
"""
import os
import sys

# Re-export all MAP classes from the main module
try:
    from ss7.attacks.map_layer import (
        MAPMessage,
        SendRoutingInfo,
        SendRoutingInfoForSM,
        SendRoutingInfoForGPRS,
        ProvideSubscriberInfo,
        AnyTimeInterrogation,
        SendIMSI,
        UpdateLocation,
        CancelLocation,
        MTForwardSM,
        SendAuthenticationInfo,
        InsertSubscriberData,
        PurgeMS,
    )
    from ss7.attacks.asn1_utils import decode_tbcd, encode_tbcd, encode_msisdn
    from ss7.attacks.tcap_layer import decode_tcap, TCAP_BEGIN, TCAP_END, TCAP_CONTINUE
except ImportError:
    pass


def parse_map_response(data):
    """
    Parse a raw MAP response and extract key information.
    
    Args:
        data: Raw bytes from network response
        
    Returns:
        dict with parsed fields
    """
    result = {
        'success': False,
        'type': None,
        'otid': None,
        'dtid': None,
        'raw_components': None,
        'error': None,
    }
    
    if not data or len(data) < 2:
        result['error'] = "No data or response too short"
        return result
    
    try:
        tcap = decode_tcap(data)
        result['type'] = tcap.get('type')
        result['otid'] = tcap.get('otid')
        result['dtid'] = tcap.get('dtid')
        result['raw_components'] = tcap.get('components')
        
        if tcap['type'] in [TCAP_END, TCAP_CONTINUE]:
            result['success'] = True
    except Exception as e:
        result['error'] = str(e)
    
    return result


def extract_imsi_from_response(data):
    """
    Try to extract IMSI from MAP response data.
    IMSI is encoded in TBCD format, typically after specific tag sequences.
    
    Args:
        data: Raw bytes from MAP response
        
    Returns:
        str: IMSI if found, None otherwise
    """
    if not data or len(data) < 8:
        return None
    
    # Look for IMSI patterns (TBCD encoded, 7-8 bytes)
    for i in range(len(data) - 8):
        # Check for potential IMSI tag patterns
        if data[i] == 0x04 and 7 <= data[i+1] <= 8:
            # Potential OCTET STRING containing IMSI
            length = data[i+1]
            if i + 2 + length <= len(data):
                try:
                    imsi = decode_tbcd(data[i+2:i+2+length])
                    # IMSI: 15 digits, starts with MCC (2-3 digits)
                    if imsi.isdigit() and 14 <= len(imsi) <= 15:
                        return imsi
                except (ValueError, IndexError, TypeError):
                    pass
        
        # Context-specific [0] containing IMSI
        if data[i] == 0x80 and 7 <= data[i+1] <= 8:
            length = data[i+1]
            if i + 2 + length <= len(data):
                try:
                    imsi = decode_tbcd(data[i+2:i+2+length])
                    if imsi.isdigit() and 14 <= len(imsi) <= 15:
                        return imsi
                except (ValueError, IndexError, TypeError):
                    pass
    
    return None


def extract_address_from_response(data):
    """
    Try to extract ISDN addresses (MSC, VLR, SGSN GT) from MAP response.
    
    Args:
        data: Raw bytes from MAP response
        
    Returns:
        list of str: Extracted addresses
    """
    addresses = []
    
    if not data or len(data) < 4:
        return addresses
    
    for i in range(len(data) - 4):
        # Look for ISDN-AddressString pattern: 0x91 followed by TBCD
        if data[i] in [0x04, 0x80, 0x81, 0x82, 0x83, 0x84]:
            length = data[i+1] if i+1 < len(data) else 0
            if 3 <= length <= 10 and i + 2 + length <= len(data):
                potential = data[i+2:i+2+length]
                if len(potential) > 0 and potential[0] == 0x91:
                    try:
                        addr = decode_tbcd(potential[1:])
                        if addr.isdigit() and len(addr) >= 6:
                            addresses.append(addr)
                    except (ValueError, IndexError, TypeError):
                        pass
    
    return addresses


def format_hex_dump(data, max_bytes=64):
    """
    Format binary data as a hex dump string.
    
    Args:
        data: bytes to display
        max_bytes: maximum bytes to show
        
    Returns:
        str: Formatted hex dump
    """
    lines = []
    for i in range(0, min(len(data), max_bytes), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        lines.append(f"{i:04x}: {hex_part:<48} {ascii_part}")
    return '\n'.join(lines)
