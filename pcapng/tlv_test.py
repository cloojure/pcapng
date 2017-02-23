# Copyright 2017 Brocade Communications Systems, Inc
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import pytest
import math
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

#-----------------------------------------------------------------------------
def test_float32():
    sqrt_2 = math.sqrt(2)
    for x in util.fibonacci_range_signed( pow(2,77) ):
        float_val = float( x + sqrt_2 )
        packed_bytes = tlv.float32_pack(float_val)
        assert len(packed_bytes) == 8
        float_val_unpacked = tlv.float32_unpack(packed_bytes)
        util.assert_rel_equal( float_val, float_val_unpacked, digits=5 )

def test_float64():
    sqrt_2 = math.sqrt(2)
    for x in util.fibonacci_range_signed( pow(2,77) ):
        dbl_val = float( x + sqrt_2 )
        packed_bytes = tlv.float64_pack(dbl_val)
        assert len(packed_bytes) == 12
        dbl_val_unpacked = tlv.float64_unpack(packed_bytes)
        util.assert_rel_equal( dbl_val, dbl_val_unpacked, digits=12 )

