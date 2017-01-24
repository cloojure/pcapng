import struct
import pytest
import pcapng.util
from pcapng.util import to_bytes, str_to_bytes

def test_block32_pad_len():
    assert 0 == pcapng.util.block32_ceil_num_bytes(0)

    assert 4 == pcapng.util.block32_ceil_num_bytes(1)
    assert 4 == pcapng.util.block32_ceil_num_bytes(2)
    assert 4 == pcapng.util.block32_ceil_num_bytes(3)
    assert 4 == pcapng.util.block32_ceil_num_bytes(4)

    assert 8 == pcapng.util.block32_ceil_num_bytes(5)
    assert 8 == pcapng.util.block32_ceil_num_bytes(6)
    assert 8 == pcapng.util.block32_ceil_num_bytes(7)
    assert 8 == pcapng.util.block32_ceil_num_bytes(8)

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
    assert to_bytes( [                      ] ) == pcapng.util.block32_pad_bytes([])
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

def test_block32_bytes_pack():
    def assert_block32_bytes_packing( data_bytes ):
        orig = to_bytes( data_bytes )
        extra_bytes = to_bytes('dummy-start') + orig + to_bytes('dummy-end')
        unpacked, remaining = pcapng.util.block32_bytes_unpack_rolling(
                              pcapng.util.block32_bytes_pack(orig) + extra_bytes )
        assert unpacked  == orig
        assert remaining == extra_bytes
    assert_block32_bytes_packing( '' )
    assert_block32_bytes_packing( 'a' )
    assert_block32_bytes_packing( 'go' )
    assert_block32_bytes_packing( 'ray' )
    assert_block32_bytes_packing( 'Doh!' )
    assert_block32_bytes_packing( 'How do you like me now?' )
    for i in range(23):
        assert_block32_bytes_packing( range(i) )

def test_block32_labelled_bytes_pack():
    block_label = pcapng.util.curr_utc_secs()
    def assert_block32_labelled_bytes_packing( data_bytes ):
        orig = to_bytes( data_bytes )
        extra_bytes = to_bytes('dummy-start') + orig + to_bytes('dummy-end')
        label, unpacked, remaining = pcapng.util.block32_labelled_bytes_unpack_rolling(
                                     pcapng.util.block32_labelled_bytes_pack( block_label, orig ) + extra_bytes )
        assert label     == block_label
        assert unpacked  == orig
        assert remaining == extra_bytes
    assert_block32_labelled_bytes_packing( '' )
    assert_block32_labelled_bytes_packing( 'a' )
    assert_block32_labelled_bytes_packing( 'go' )
    assert_block32_labelled_bytes_packing( 'ray' )
    assert_block32_labelled_bytes_packing( 'Doh!' )
    assert_block32_labelled_bytes_packing( 'How do you like me now?' )
    for i in range(13):
        assert_block32_labelled_bytes_packing( range(i) )

#-----------------------------------------------------------------------------

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
    with pytest.raises(AssertionError): pcapng.util.assert_uint8(  -1 )
    with pytest.raises(AssertionError): pcapng.util.assert_uint8( 256 )

def test_int8():
    for sb in range(-128,127):
        pcapng.util.assert_int8(sb)
    with pytest.raises(AssertionError): pcapng.util.assert_int8( -129 )
    with pytest.raises(AssertionError): pcapng.util.assert_int8(  128 )

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

def test_ipAddr_codec():
    ip_bytes = pcapng.util.ipAddr_encode( [97,98,99,100] )
    assert len( ip_bytes )  ==  4
    assert ip_bytes[0]      == to_bytes( [97] )
    assert ip_bytes[3]      == to_bytes( [100] )
    assert pcapng.util.ipAddr_decode( ip_bytes ) == [97,98,99,100]

#-----------------------------------------------------------------------------
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

    assert 'abc'             == pcapng.util.chrList_to_str(['a', 'b', 'c'])

def test_time():
    pcapng.util.test_time_utc_set(123.456789)
    (secs,usecs) = pcapng.util.curr_utc_timetuple()
    assert 123    == secs
    assert 456789 == round( usecs )
    pcapng.util.test_time_utc_unset()

    pcapng.util.test_time_utc_set(123456)
    assert '0x0001e240' == pcapng.util.curr_utc_secs_hexstr()
    pcapng.util.test_time_utc_unset()
