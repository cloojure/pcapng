import pytest
import struct
import pcapng.tlv  as tlv
import pcapng.util as util
from   pcapng.util import to_bytes

#-----------------------------------------------------------------------------
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

def test_uint64():
    for val in util.fibonacci_range( pow(2,64) ):
        packed_bytes = tlv.uint64_pack(val)
        assert len(packed_bytes) == 12
        val_unpacked = tlv.uint64_unpack(packed_bytes)
        assert val == val_unpacked

#-----------------------------------------------------------------------------
def test_int8():
    for val in util.fibonacci_range_signed( pow(2,7) ):
        packed_bytes = tlv.int8_pack(val)
        assert len(packed_bytes) == 8
        val_unpacked = tlv.int8_unpack(packed_bytes)
        assert val == val_unpacked

def test_int16():
    for val in util.fibonacci_range_signed( pow(2,15) ):
        packed_bytes = tlv.int16_pack(val)
        assert len(packed_bytes) == 8
        val_unpacked = tlv.int16_unpack(packed_bytes)
        assert val == val_unpacked

def test_int32():
    for val in util.fibonacci_range_signed( pow(2,31) ):
        packed_bytes = tlv.int32_pack(val)
        assert len(packed_bytes) == 8
        val_unpacked = tlv.int32_unpack(packed_bytes)
        assert val == val_unpacked

def test_int64():
    for val in util.fibonacci_range_signed( pow(2,63) ):
        packed_bytes = tlv.int64_pack(val)
        assert len(packed_bytes) == 12
        val_unpacked = tlv.int64_unpack(packed_bytes)
        assert val == val_unpacked

