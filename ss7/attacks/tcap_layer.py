#!/usr/bin/env python
"""
TCAP (Transaction Capabilities Application Part) Layer for SS7
Implements TCAP message encoding according to ITU-T Q.773
"""

from .asn1_utils import *

# TCAP Message Types (Application tags)
TCAP_BEGIN = 0x62          # [APPLICATION 2] Begin
TCAP_END = 0x64            # [APPLICATION 4] End  
TCAP_CONTINUE = 0x65       # [APPLICATION 5] Continue
TCAP_ABORT = 0x67          # [APPLICATION 7] Abort
TCAP_UNIDIRECTIONAL = 0x61 # [APPLICATION 1] Unidirectional

# TCAP Component Types
COMP_INVOKE = 0xA1         # [CONTEXT 1] Invoke
COMP_RETURN_RESULT = 0xA2  # [CONTEXT 2] ReturnResult
COMP_RETURN_ERROR = 0xA3   # [CONTEXT 3] ReturnError
COMP_REJECT = 0xA4         # [CONTEXT 4] Reject

# TCAP Parameter Tags
TAG_OTID = 0x48            # Originating Transaction ID
TAG_DTID = 0x49            # Destination Transaction ID
TAG_COMPONENT_PORTION = 0x6C
TAG_DIALOGUE_PORTION = 0x6B
TAG_INVOKE_ID = 0x02       # INTEGER
TAG_OPERATION_CODE = 0x02  # INTEGER (local)

class TCAPMessage:
    """Base class for TCAP messages."""
    
    def __init__(self):
        self.otid = None
        self.dtid = None
        self.components = []
    
    def set_transaction_ids(self, otid, dtid=None):
        """Set transaction IDs."""
        self.otid = otid
        self.dtid = dtid
    
    def add_component(self, component):
        """Add a component to the message."""
        self.components.append(component)

class TCAPInvoke:
    """TCAP Invoke component."""
    
    def __init__(self, invoke_id, operation_code, parameter=None):
        self.invoke_id = invoke_id
        self.operation_code = operation_code
        self.parameter = parameter
    
    def encode(self):
        """Encode Invoke component."""
        content = b''
        
        # Invoke ID
        content += encode_integer(self.invoke_id)
        
        # Operation Code (local)
        op_code = encode_integer(self.operation_code)
        content += encode_context_tag(2, op_code, constructed=True)
        
        # Parameter (if any)
        if self.parameter:
            content += encode_context_tag(0, self.parameter, constructed=True)
        
        return encode_tlv(bytes([COMP_INVOKE]), content)

class TCAPReturnResult:
    """TCAP ReturnResult component."""
    
    def __init__(self, invoke_id, operation_code=None, parameter=None):
        self.invoke_id = invoke_id
        self.operation_code = operation_code
        self.parameter = parameter
    
    def encode(self):
        """Encode ReturnResult component."""
        content = b''
        
        # Invoke ID
        content += encode_integer(self.invoke_id)
        
        # Result-RetRes (SEQUENCE of opCode + parameter)
        if self.operation_code is not None:
            result_content = encode_integer(self.operation_code)
            if self.parameter:
                result_content += self.parameter
            content += encode_sequence(result_content)
        
        return encode_tlv(bytes([COMP_RETURN_RESULT]), content)

def encode_tcap_begin(otid, components_data, dialogue_portion=None):
    """
    Encode a TCAP Begin message.
    
    Args:
        otid: Originating Transaction ID (bytes or int)
        components_data: Encoded component portion
        dialogue_portion: Optional encoded dialogue portion (Application Context, etc.)
    
    Returns:
        bytes: Complete TCAP Begin message
    """
    content = b''
    
    # Originating Transaction ID
    if isinstance(otid, int):
        otid = otid.to_bytes(4, 'big')
    content += encode_tlv(bytes([TAG_OTID]), otid)
    
    # Dialogue Portion (optional but recommended for HLR compatibility)
    if dialogue_portion:
        content += encode_tlv(bytes([TAG_DIALOGUE_PORTION]), dialogue_portion)
    
    # Component Portion
    content += encode_tlv(bytes([TAG_COMPONENT_PORTION]), components_data)
    
    return encode_tlv(bytes([TCAP_BEGIN]), content)

def encode_tcap_continue(otid, dtid, components_data):
    """Encode a TCAP Continue message."""
    content = b''
    
    if isinstance(otid, int):
        otid = otid.to_bytes(4, 'big')
    if isinstance(dtid, int):
        dtid = dtid.to_bytes(4, 'big')
    
    content += encode_tlv(bytes([TAG_OTID]), otid)
    content += encode_tlv(bytes([TAG_DTID]), dtid)
    content += encode_tlv(bytes([TAG_COMPONENT_PORTION]), components_data)
    
    return encode_tlv(bytes([TCAP_CONTINUE]), content)

def encode_tcap_end(dtid, components_data):
    """Encode a TCAP End message."""
    content = b''
    
    if isinstance(dtid, int):
        dtid = dtid.to_bytes(4, 'big')
    
    content += encode_tlv(bytes([TAG_DTID]), dtid)
    content += encode_tlv(bytes([TAG_COMPONENT_PORTION]), components_data)
    
    return encode_tlv(bytes([TCAP_END]), content)

def encode_tcap_unidirectional(components_data):
    """Encode a TCAP Unidirectional message (no transaction IDs)."""
    content = encode_tlv(bytes([TAG_COMPONENT_PORTION]), components_data)
    return encode_tlv(bytes([TCAP_UNIDIRECTIONAL]), content)

def build_map_dialogue_portion(application_context_name_oid):
    """
    Build MAP Dialogue Portion with Application Context Name.
    This is often required by HLRs to accept MAP operations.
    
    Args:
        application_context_name_oid: OID as list of integers
            e.g. [0, 4, 0, 0, 1, 0, 20, 3] for shortMsgGateway-v3
    
    Returns:
        bytes: Encoded dialogue portion content
    
    Common MAP Application Context OIDs:
    - [0, 4, 0, 0, 1, 0, 25, 3]: networkLocUp-v3 (Update Location)
    - [0, 4, 0, 0, 1, 0, 20, 3]: shortMsgGateway-v3 (SMS)
    - [0, 4, 0, 0, 1, 0, 21, 3]: shortMsgMO-Relay-v3
    - [0, 4, 0, 0, 1, 0, 71, 1]: anyTimeEnquiry-v3 (ATI, PSI)
    """
    from .asn1_utils import encode_tlv, encode_sequence, TAG_OID
    
    # Encode OID
    oid_bytes = bytes([len(application_context_name_oid)] + application_context_name_oid)
    ac_name = encode_tlv(TAG_OID, oid_bytes)
    
    # External tag [UNIVERSAL 8] - indicates dialogue PDU
    # Dialogue Request
    dialogue_request = encode_sequence(
        encode_context_tag(0, ac_name, constructed=False)  # application-context-name
    )
    
    # AARQ-apdu [APPLICATION 0]
    aarq = encode_tlv(bytes([0x60]), dialogue_request)
    
    # External wrapper
    external_content = encode_tlv(bytes([0x06]), b'\x00\x11\x86\x05\x01\x01\x01')  # direct-reference OID
    external_content += encode_context_tag(0, aarq, constructed=True)  # encoding: single-ASN1-type
    
    return encode_tlv(bytes([0x28]), external_content)  # EXTERNAL tag

def decode_tcap(data):
    """
    Decode a TCAP message.
    Returns dict with message type, transaction IDs, and components.
    """
    result = {
        'type': None,
        'otid': None,
        'dtid': None,
        'components': []
    }
    
    if len(data) < 2:
        return result
    
    msg_type = data[0]
    result['type'] = msg_type
    
    # Parse length
    idx = 1
    if data[idx] & 0x80:
        len_bytes = data[idx] & 0x7F
        length = int.from_bytes(data[idx+1:idx+1+len_bytes], 'big')
        idx += 1 + len_bytes
    else:
        length = data[idx]
        idx += 1
    
    # Parse content
    end = idx + length
    while idx < end:
        tag = data[idx]
        idx += 1
        
        if data[idx] & 0x80:
            len_bytes = data[idx] & 0x7F
            val_len = int.from_bytes(data[idx+1:idx+1+len_bytes], 'big')
            idx += 1 + len_bytes
        else:
            val_len = data[idx]
            idx += 1
        
        value = data[idx:idx+val_len]
        idx += val_len
        
        if tag == TAG_OTID:
            result['otid'] = value
        elif tag == TAG_DTID:
            result['dtid'] = value
        elif tag == TAG_COMPONENT_PORTION:
            result['components'] = value
    
    return result
