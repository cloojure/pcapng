import pytest
import struct
import pcapng.tlv  as tlv
import pcapng.util as util
from   pcapng.util import to_bytes

def test_uint8():
    for val in util.fibonacci_range( pow(2,8) ):
        packed_bytes = tlv.uint8_pack(val)
        assert len(packed_bytes) == 8
        val_unpacked = tlv.uint8_unpack(packed_bytes)
        assert val == val_unpacked

def test_uint16():
    for val in util.fibonacci_range( pow(2,16) ):
        packed_bytes = tlv.uint16_pack(val)
        assert len(packed_bytes) == 8
        val_unpacked = tlv.uint16_unpack(packed_bytes)
        assert val == val_unpacked

def test_uint32():
    for val in util.fibonacci_range( pow(2,32) ):
        packed_bytes = tlv.uint32_pack(val)
        assert len(packed_bytes) == 8
        val_unpacked = tlv.uint32_unpack(packed_bytes)
        assert val == val_unpacked


