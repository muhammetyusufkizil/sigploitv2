#!/usr/bin/env python
"""
ASN.1 BER Encoding Utilities for SS7/TCAP/MAP
Provides basic BER encoding/decoding for SS7 protocol messages.
"""

# ASN.1 Tag Classes
TAG_CLASS_UNIVERSAL = 0x00
TAG_CLASS_APPLICATION = 0x40
TAG_CLASS_CONTEXT = 0x80
TAG_CLASS_PRIVATE = 0xC0

# ASN.1 Universal Tags
TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_SET = 0x31

def encode_length(length):
    """Encode ASN.1 length field."""
    if length < 128:
        return bytes([length])
    elif length < 256:
        return bytes([0x81, length])
    elif length < 65536:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])

def encode_tag(tag_class, constructed, tag_number):
    """Encode ASN.1 tag."""
    tag = tag_class
    if constructed:
        tag |= 0x20
    if tag_number < 31:
        tag |= tag_number
        return bytes([tag])
    else:
        tag |= 0x1F
        result = [tag]
        if tag_number < 128:
            result.append(tag_number)
        else:
            octets = []
            while tag_number > 0:
                octets.insert(0, (tag_number & 0x7F) | (0x80 if octets else 0))
                tag_number >>= 7
            result.extend(octets)
        return bytes(result)

def encode_tlv(tag, value):
    """Encode a complete TLV (Tag-Length-Value)."""
    if isinstance(tag, int):
        tag_bytes = bytes([tag])
    else:
        tag_bytes = tag
    length_bytes = encode_length(len(value))
    return tag_bytes + length_bytes + value

def encode_integer(value):
    """Encode an integer in ASN.1 BER format."""
    if value == 0:
        return encode_tlv(TAG_INTEGER, bytes([0]))
    
    negative = value < 0
    if negative:
        # Two's complement for negative
        value = -value
        
    result = []
    while value > 0:
        result.insert(0, value & 0xFF)
        value >>= 8
    
    # Add padding if needed
    if not negative and result[0] & 0x80:
        result.insert(0, 0x00)
    elif negative:
        # Convert to two's complement
        for i in range(len(result)):
            result[i] = ~result[i] & 0xFF
        # Add 1
        carry = 1
        for i in range(len(result) - 1, -1, -1):
            result[i] += carry
            carry = result[i] >> 8
            result[i] &= 0xFF
        if not (result[0] & 0x80):
            result.insert(0, 0xFF)
    
    return encode_tlv(TAG_INTEGER, bytes(result))

def encode_octet_string(data):
    """Encode octet string."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return encode_tlv(TAG_OCTET_STRING, data)

def encode_sequence(content):
    """Encode a SEQUENCE."""
    return encode_tlv(TAG_SEQUENCE, content)

def encode_context_tag(tag_num, value, constructed=False):
    """Encode a context-specific tag."""
    tag = TAG_CLASS_CONTEXT | tag_num
    if constructed:
        tag |= 0x20
    return encode_tlv(bytes([tag]), value)

def encode_tbcd(number_str):
    """
    Encode a number string to TBCD (Telephony BCD) format.
    Used for IMSI, MSISDN encoding.
    """
    result = []
    # Pad with F if odd length
    if len(number_str) % 2 == 1:
        number_str += 'F'
    
    for i in range(0, len(number_str), 2):
        low = int(number_str[i], 16) if number_str[i] != 'F' else 0xF
        high = int(number_str[i+1], 16) if number_str[i+1] != 'F' else 0xF
        result.append((high << 4) | low)
    
    return bytes(result)

def decode_tbcd(data):
    """Decode TBCD to number string."""
    result = ""
    for byte in data:
        low = byte & 0x0F
        high = (byte >> 4) & 0x0F
        if low != 0xF:
            result += hex(low)[2:]
        if high != 0xF:
            result += hex(high)[2:]
    return result

def encode_imsi(imsi_str):
    """Encode IMSI with type indicator."""
    # IMSI: First byte is type (0x91 = international), rest is TBCD
    tbcd = encode_tbcd(imsi_str)
    return bytes([len(tbcd) + 1, 0x91]) + tbcd

def encode_msisdn(msisdn_str):
    """Encode MSISDN/ISDN address."""
    # MSISDN: type-of-number + numbering-plan + TBCD digits
    # 0x91 = International number, ISDN numbering plan
    tbcd = encode_tbcd(msisdn_str)
    return bytes([0x91]) + tbcd

def encode_global_title(gt_str, gt_type=0x12):
    """
    Encode Global Title for SCCP.
    gt_type: 0x12 = Translation type + numbering plan + encoding scheme + nature
    """
    tbcd = encode_tbcd(gt_str)
    # GT format: Translation type(1) + Numbering plan(4bits) + Encoding(4bits) + Nature(1) + Digits
    return bytes([0x00, 0x12, 0x04]) + tbcd
