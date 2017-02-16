"""Implements Type-Length-Value (TLV) packing of generic values along 32-bit words, with
trailing padding supplied as required."""

import struct
import pcapng.util      as util
from   pcapng.util      import to_bytes

#todo need a generic version that accepts an endian flag
#todo need a specialized version that sets/reads global endian flag based on hdr blocks

#todo think about how to handle a block of packets
#todo look at "docopt" usage -> cmdopts processing

#-----------------------------------------------------------------------------
util.assert_python2()    #todo make work for python 2.7 or 3.3 ?
#-----------------------------------------------------------------------------
#todo check type on all fns
#todo verify have tests for all

# 16-bit type values
STRING_UTF8     = 100

UINT8           = 201
UINT16          = 202
UINT32          = 204
UINT64          = 208

INT8            = 301
INT16           = 302
INT32           = 304
INT64           = 308

FLOAT32         = 404
FLOAT64         = 408

# IPV4            = 504
# IPV6            = 506
# IPV4_CIDR       = 514  # 4 bytes each addr & mask?
# IPV6_CIDR       = 516  # 4 bytes each addr & mask?


#todo add integer_pack/unpack
#todo add float_pack/unpack
#todo add string pack/unpack ?  (noop?)
#todo add other pack/unpack ?

#-----------------------------------------------------------------------------
def uint8_pack(value):
    packed_bytes = util.block32_pad_bytes( struct.pack( '=HHB', UINT8, 1, value ))
    return packed_bytes
def uint8_unpack(packed_bytes):
    util.assert_type_bytes(packed_bytes)
    assert len(packed_bytes) == 8
    (type, length, value) = struct.unpack( '=HHB', packed_bytes[:5] )   #todo use endian flag
    assert (type, length) == (UINT8, 1)
    return value

def uint16_pack(value):
    packed_bytes = util.block32_pad_bytes( struct.pack( '=HHH', UINT16, 2, value ))
    return packed_bytes
def uint16_unpack(packed_bytes):
    util.assert_type_bytes(packed_bytes)
    assert len(packed_bytes) == 8
    (type, length, value) = struct.unpack( '=HHH', packed_bytes[:6] )   #todo use endian flag
    assert (type, length) == (UINT16, 2)
    return value

def uint32_pack(value):
    packed_bytes = util.block32_pad_bytes( struct.pack( '=HHL', UINT32, 4, value ))
    return packed_bytes
def uint32_unpack(packed_bytes):
    util.assert_type_bytes(packed_bytes)
    assert len(packed_bytes) == 8
    (type, length, value) = struct.unpack( '=HHL', packed_bytes[:8] )   #todo use endian flag
    assert (type, length) == (UINT32, 4)
    return value

def uint64_pack(value):
    packed_bytes = util.block32_pad_bytes( struct.pack( '=HHQ', UINT64, 8, value ))
    return packed_bytes
def uint64_unpack(packed_bytes):
    util.assert_type_bytes(packed_bytes)
    assert len(packed_bytes) == 12
    (type, length, value) = struct.unpack( '=HHQ', packed_bytes[:12] )   #todo use endian flag
    assert (type, length) == (UINT64, 8)
    return value

#-----------------------------------------------------------------------------
def int8_pack(value):
    packed_bytes = util.block32_pad_bytes( struct.pack( '=HHb', INT8, 1, value ))
    return packed_bytes
def int8_unpack(packed_bytes):
    util.assert_type_bytes(packed_bytes)
    assert len(packed_bytes) == 8
    (type, length, value) = struct.unpack( '=HHb', packed_bytes[:5] )   #todo use endian flag
    assert (type, length) == (INT8, 1)
    return value

def int16_pack(value):
    packed_bytes = util.block32_pad_bytes( struct.pack( '=HHh', INT16, 2, value ))
    return packed_bytes
def int16_unpack(packed_bytes):
    util.assert_type_bytes(packed_bytes)
    assert len(packed_bytes) == 8
    (type, length, value) = struct.unpack( '=HHh', packed_bytes[:6] )   #todo use endian flag
    assert (type, length) == (INT16, 2)
    return value

def int32_pack(value):
    packed_bytes = util.block32_pad_bytes( struct.pack( '=HHl', INT32, 4, value ))
    return packed_bytes
def int32_unpack(packed_bytes):
    util.assert_type_bytes(packed_bytes)
    assert len(packed_bytes) == 8
    (type, length, value) = struct.unpack( '=HHl', packed_bytes[:8] )   #todo use endian flag
    assert (type, length) == (INT32, 4)
    return value

def int64_pack(value):
    packed_bytes = util.block32_pad_bytes( struct.pack( '=HHq', INT64, 8, value ))
    return packed_bytes
def int64_unpack(packed_bytes):
    util.assert_type_bytes(packed_bytes)
    assert len(packed_bytes) == 12
    (type, length, value) = struct.unpack( '=HHq', packed_bytes[:12] )   #todo use endian flag
    assert (type, length) == (INT64, 8)
    return value

#-----------------------------------------------------------------------------
def float32_pack(value):
    packed_bytes = util.block32_pad_bytes( struct.pack( '=HHf', FLOAT32, 4, value ))
    return packed_bytes
def float32_unpack(packed_bytes):
    util.assert_type_bytes(packed_bytes)
    assert len(packed_bytes) == 8
    (type, length, value) = struct.unpack( '=HHf', packed_bytes[:8] )   #todo use endian flag
    assert (type, length) == (FLOAT32, 4)
    return value

def float64_pack(value):   #todo need double_pack/unpack synonym?
    packed_bytes = util.block32_pad_bytes( struct.pack( '=HHd', FLOAT64, 8, value ))
    return packed_bytes
def float64_unpack(packed_bytes):
    util.assert_type_bytes(packed_bytes)
    assert len(packed_bytes) == 12
    (type, length, value) = struct.unpack( '=HHd', packed_bytes[:12] )   #todo use endian flag
    assert (type, length) == (FLOAT64, 8)
    return value

#-----------------------------------------------------------------------------
def string_utf8_pack( str_val ):
    content = to_bytes( str_val )
    packed_bytes = util.block32_pad_bytes(
        struct.pack( '=HH', STRING_UTF8, len(content) ) + content )
    return packed_bytes
def string_utf8_unpack( packed_bytes ):
    util.assert_type_bytes(packed_bytes)
    (type, length) = struct.unpack( '=HH', packed_bytes[:4] )   #todo use endian flag
    content_pad = packed_bytes[4:]
    assert type == STRING_UTF8
    assert 0 <= length <= len(content_pad)
    content = str( content_pad[:length] )
    return content


