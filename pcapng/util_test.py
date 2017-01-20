import struct
import time
import pytest
import pcapng.util
from pcapng.util import to_bytes, str_to_bytes

def test_block32_pad_len():
    assert 0 == pcapng.util.block32_ceil_bytes(0)

    assert 4 == pcapng.util.block32_ceil_bytes(1)
    assert 4 == pcapng.util.block32_ceil_bytes(2)
    assert 4 == pcapng.util.block32_ceil_bytes(3)
    assert 4 == pcapng.util.block32_ceil_bytes(4)

    assert 8 == pcapng.util.block32_ceil_bytes(5)
    assert 8 == pcapng.util.block32_ceil_bytes(6)
    assert 8 == pcapng.util.block32_ceil_bytes(7)
    assert 8 == pcapng.util.block32_ceil_bytes(8)

def test_pad_to_len():
    with pytest.raises(AssertionError): pcapng.util.pad_bytes([1, 2, 3, 4], 3)
    with pytest.raises(AssertionError): pcapng.util.pad_bytes('superlong', 3)

    assert to_bytes( 'superlong' + chr(0)*23 ) == pcapng.util.pad_bytes('superlong', 32)
    assert to_bytes( [0, 0, 0, 0] ) == pcapng.util.pad_bytes([          ], 4)
    assert to_bytes( [1, 0, 0, 0] ) == pcapng.util.pad_bytes([1, ], 4)
    assert to_bytes( [1, 2, 0, 0] ) == pcapng.util.pad_bytes([1, 2], 4)
    assert to_bytes( [1, 2, 3, 0] ) == pcapng.util.pad_bytes([1, 2, 3], 4)
    assert to_bytes( [1, 2, 3, 4] ) == pcapng.util.pad_bytes([1, 2, 3, 4], 4)

    assert to_bytes( [9, 9, 9, 9] ) == pcapng.util.pad_bytes([          ], 4, 9)
    assert to_bytes( [1, 9, 9, 9] ) == pcapng.util.pad_bytes([1, ], 4, 9)
    assert to_bytes( [1, 2, 9, 9] ) == pcapng.util.pad_bytes([1, 2], 4, 9)
    assert to_bytes( [1, 2, 3, 9] ) == pcapng.util.pad_bytes([1, 2, 3], 4, 9)
    assert to_bytes( [1, 2, 3, 4] ) == pcapng.util.pad_bytes([1, 2, 3, 4], 4, 9)

def test_pad_to_block32():
    assert to_bytes( [                      ] ) == pcapng.util.block32_pad_bytes([                      ])
    assert to_bytes( [1, 0, 0, 0            ] ) == pcapng.util.block32_pad_bytes([1])
    assert to_bytes( [1, 2, 0, 0            ] ) == pcapng.util.block32_pad_bytes([1, 2])
    assert to_bytes( [1, 2, 3, 0            ] ) == pcapng.util.block32_pad_bytes([1, 2, 3])
    assert to_bytes( [1, 2, 3, 4            ] ) == pcapng.util.block32_pad_bytes([1, 2, 3, 4])
    assert to_bytes( [1, 2, 3, 4, 5, 0, 0, 0] ) == pcapng.util.block32_pad_bytes([1, 2, 3, 4, 5])
    assert to_bytes( [1, 2, 3, 4, 5, 6, 0, 0] ) == pcapng.util.block32_pad_bytes([1, 2, 3, 4, 5, 6])
    assert to_bytes( [1, 2, 3, 4, 5, 6, 7, 0] ) == pcapng.util.block32_pad_bytes([1, 2, 3, 4, 5, 6, 7])
    assert to_bytes( [1, 2, 3, 4, 5, 6, 7, 8] ) == pcapng.util.block32_pad_bytes([1, 2, 3, 4, 5, 6, 7, 8])

    pcapng.util.assert_block32_length([                      ])
    pcapng.util.assert_block32_length([1, 2, 3, 4])
    pcapng.util.assert_block32_length([1, 2, 3, 4, 5, 6, 7, 8])
    with pytest.raises(AssertionError): pcapng.util.assert_block32_length([1])
    with pytest.raises(AssertionError): pcapng.util.assert_block32_length([1, 2])
    with pytest.raises(AssertionError): pcapng.util.assert_block32_length([1, 2, 3])


def test_xxx():
    xx1 = struct.pack(   '!hhl', 1, 2, 3 )  # h='short', l='long'
    xx2 = struct.unpack( '!hhl', xx1 )      # ! => network byte order (big-endian)
    assert xx1 == '\x00\x01\x00\x02\x00\x00\x00\x03'
    assert xx2 == ( 1, 2, 3 )
    assert '\x00\x00\x00\x00\x00\x00\x00\x05' == struct.pack( '!q', 5 )
    assert '\x00\x00\x00\x05'                 == struct.pack( '!l', 5 )
    assert '\x00\x05'                         == struct.pack( '!h', 5 )
    assert 1 == pcapng.util.first( [1,2,3] )

    assert 3 == len( [ 1, 2, 3] )
    assert (3, 140000) == pcapng.util.split_float(3.14)
    assert (3, 141593) == pcapng.util.split_float(3.141592654)

    assert 'abc'             == pcapng.util.ChrList_to_str(['a', 'b', 'c'])

    ts1 = pcapng.util.curr_utc_time_tuple()
    time.sleep(0.1)
    delta = pcapng.util.timetup_subtract( ts1, pcapng.util.curr_utc_time_tuple() )
    assert ((0.09 < delta) and (delta < 0.11))

def test_types():
    pcapng.util.assert_type_str('')
    pcapng.util.assert_type_str('a')
    pcapng.util.assert_type_str('abc')

    pcapng.util.assert_type_list( [] )
    pcapng.util.assert_type_list( [1] )
    pcapng.util.assert_type_list( [1,2,3,] )

    pcapng.util.assert_type_dict( {} )
    pcapng.util.assert_type_dict( {'a':1} )
    pcapng.util.assert_type_dict( {'a':1, 'b':2} )

    with pytest.raises(AssertionError): pcapng.util.assert_type_str( None )
    with pytest.raises(AssertionError): pcapng.util.assert_type_str( [1] )
    with pytest.raises(AssertionError): pcapng.util.assert_type_str( {'a':1} )

    with pytest.raises(AssertionError): pcapng.util.assert_type_list( None )
    with pytest.raises(AssertionError): pcapng.util.assert_type_list( 'a' )
    with pytest.raises(AssertionError): pcapng.util.assert_type_list( {'a':1} )

    with pytest.raises(AssertionError): pcapng.util.assert_type_dict( None )
    with pytest.raises(AssertionError): pcapng.util.assert_type_dict( 'a' )
    with pytest.raises(AssertionError): pcapng.util.assert_type_dict( [1] )


def test_uint8():
    for ub in range(256):
        pcapng.util.assert_uint8(ub)
    with pytest.raises(AssertionError): pcapng.util.assert_uint8(-1)
    with pytest.raises(AssertionError): pcapng.util.assert_uint8(256)

def test_int8():
    for sb in range(-128,127):
        pcapng.util.assert_int8(sb)
    with pytest.raises(AssertionError): pcapng.util.assert_int8(-129)
    with pytest.raises(AssertionError): pcapng.util.assert_int8(128)

def test_bytearray():
    pcapng.util.assert_type_bytearray( bytearray( [1,2,255] ))
    with pytest.raises(AssertionError): pcapng.util.assert_type_bytearray( list( [1,2,255] ) )
    with pytest.raises(AssertionError): pcapng.util.assert_type_bytearray( 'abc' )

def test_to_bytes():
    assert 'abc' == to_bytes( 'abc' )
    assert 'abc' == to_bytes( [97,98,99] )
    if pcapng.util.is_python2():
        assert str( 'abc' ) == to_bytes( 'abc' )
    if pcapng.util.is_python3():
        assert bytes( [97,98,99] ) == to_bytes( [97,98,99] )

def test_str_to_bytes():
    assert to_bytes( [97,98,99] ) == str_to_bytes( 'abc' )
