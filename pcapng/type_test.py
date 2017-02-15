import pytest
import struct
import pcapng.type as type
import pcapng.util as util
from   pcapng.util import to_bytes

def test_uint16():
    for val in util.fibonacci_range(65535):
        packed_bytes = type.uint16_pack(val)
        assert len(packed_bytes) == 8
        val_unpacked = type.uint16_unpack(packed_bytes)
        assert val == val_unpacked


