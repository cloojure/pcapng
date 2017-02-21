import pytest
import struct
import pcapng.option    as option
from   pcapng.option    import Option, ShbOption, IdbOption
import pcapng.pen       as pen
import pcapng.tlv       as tlv
import pcapng.util      as util
from   pcapng.util      import to_bytes

#todo add generative testing for all

def test_option_codec():
    def assert_option_codec(opt_code, opt_value):
        (opt,remaining_bytes) = option.unpack_rolling( Option(opt_code, opt_value ).pack() )
        assert opt.code     == opt_code
        assert opt.content  == to_bytes(opt_value)

    #todo add tests for opt values of string, byte, short, int, float, double
    #todo add tests for opt value len up to 9999?
    assert_option_codec( 0, [] )
    assert_option_codec( 1, [1,] )
    assert_option_codec( 2, [1,2, ] )
    assert_option_codec( 3, [1,2,3,] )
    assert_option_codec( 4, [1,2,3,4,] )
    assert_option_codec( 5, [1,2,3,4,5] )
    assert_option_codec( 0, [0] )
    assert_option_codec( 0, [5] )
    assert_option_codec( 1, [78] )
    assert_option_codec( 2, [178] )
    assert_option_codec( 2, [255] )

def test_options_codec():
    def assert_options_codec(options_lst):
        options_out = option.unpack_all( option.pack_all( options_lst ))
        assert options_out == options_lst
    assert_options_codec(  [ Option(1,'') ] )
    assert_options_codec(  [ Option(2,''),
                             Option(3,'a') ] )
    assert_options_codec(  [ Option(4,''),
                             Option(5,'a'),
                             Option(6,'Doh!') ] )

# def test_custom_option_value():
#     #todo include standalone value pack/unpack
#     #todo include pack/unpack  mixed with regular options
#     def assert_custom_option_value_codec( pen, content ):
#         value_dict_result = option.custom_option_value_unpack(
#             option.custom_option_value_pack( pen, content ))
#         assert value_dict_result[ 'pen'         ] == pen
#         assert value_dict_result[ 'content_pad' ] == util.block32_pad_bytes( content )
#             #todo use block32_bytes_pack/unpack() to avoid padding on output?
#     assert_custom_option_value_codec( pen.BROCADE_PEN, '' )
#     assert_custom_option_value_codec( pen.BROCADE_PEN, 'a' )
#     assert_custom_option_value_codec( pen.BROCADE_PEN, 'go' )
#     assert_custom_option_value_codec( pen.BROCADE_PEN, 'ray' )
#     assert_custom_option_value_codec( pen.BROCADE_PEN, 'Doh!' )
#     assert_custom_option_value_codec( pen.BROCADE_PEN, 'How do you like me now?' )
#
#     cust_val_1 = option.custom_option_value_pack( pen.BROCADE_PEN, "yo" )
#     cust_val_2 = option.custom_option_value_pack( pen.BROCADE_PEN, "Mary had a little lamb" )
#     cust_val_3 = option.custom_option_value_pack( pen.BROCADE_PEN, "don't copy me!" )
#     cust_val_4 = option.custom_option_value_pack( pen.BROCADE_PEN, 'fin' )
#     opts_lst = [
#         Option( 5, "five"           ), Option(option.CUSTOM_STRING_COPYABLE, cust_val_1),
#         Option( 6, "six"            ), Option(option.CUSTOM_BINARY_COPYABLE, cust_val_2),
#         Option( 7, "seventy-seven"  ), Option(option.CUSTOM_STRING_NON_COPYABLE, cust_val_3),
#         Option( 8, "eight"          ), Option(option.CUSTOM_BINARY_NON_COPYABLE, cust_val_4),
#         Option( 9, "9" ) ]
#     result_lst = option.unpack_all( option.pack_all( opts_lst ))
#     assert opts_lst == result_lst

def test_Comment():
    s1  = 'Five Stars!'
    c1  = option.Comment(s1)
    c1u = option.Comment.unpack( c1.pack() )
    assert c1.content == c1u.content == s1
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.Comment'

def test_CustomStringCopyable():
    s1 = 'Mary had a little lamb'
    c1  = option.CustomStringCopyable( pen.BROCADE_PEN, s1 )
    c1u = option.CustomStringCopyable.unpack( c1.pack() )
    assert c1.content == c1u.content == s1
    assert c1.pen_val == c1u.pen_val == pen.BROCADE_PEN
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.CustomStringCopyable'

def test_CustomBinaryCopyable():
    s1 = 'Mary had a binary lamb'
    c1  = option.CustomBinaryCopyable( pen.BROCADE_PEN, s1 )
    c1u = option.CustomBinaryCopyable.unpack( c1.pack() )
    assert c1.content == c1u.content == s1
    assert c1.pen_val == c1u.pen_val == pen.BROCADE_PEN
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.CustomBinaryCopyable'

def test_CustomStringNonCopyable():
    s1 = 'Mary had a non-copyable little lamb'
    c1  = option.CustomStringNonCopyable( pen.BROCADE_PEN, s1 )
    c1u = option.CustomStringNonCopyable.unpack( c1.pack() )
    assert c1.content == c1u.content == s1
    assert c1.pen_val == c1u.pen_val == pen.BROCADE_PEN
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.CustomStringNonCopyable'

def test_CustomBinaryNonCopyable():
    s1 = 'Mary had a non-copyable binary lamb'
    c1  = option.CustomBinaryNonCopyable( pen.BROCADE_PEN, s1 )
    c1u = option.CustomBinaryNonCopyable.unpack( c1.pack() )
    assert c1.content == c1u.content == s1
    assert c1.pen_val == c1u.pen_val == pen.BROCADE_PEN
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.CustomBinaryNonCopyable'

#-----------------------------------------------------------------------------
def test_ShbHardware():
    s1 = 'x86 water heater'
    c1  = option.ShbHardware(s1)
    c1u = option.ShbHardware.unpack( c1.pack() )
    assert c1.content == c1u.content == s1
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.ShbHardware'
def test_ShbOs():
    s1 = 'x86 water heater'
    c1  = option.ShbOs(s1)
    c1u = option.ShbOs.unpack( c1.pack() )
    assert c1.content == c1u.content == s1
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.ShbOs'
def test_ShbUserAppl():
    s1 = 'x86 water heater'
    c1  = option.ShbUserAppl(s1)
    c1u = option.ShbUserAppl.unpack( c1.pack() )
    assert c1.content == c1u.content == s1
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.ShbUserAppl'

#-----------------------------------------------------------------------------
def test_IdbName():
    s1 = 'ifc downlow'
    c1  = option.IdbName(s1)
    c1u = option.IdbName.unpack( c1.pack() )
    assert c1.content == c1u.content == s1
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.IdbName'

def test_IdbDescription():
    s1 = 'ifc supercool'
    c1  = option.IdbDescription(s1)
    c1u = option.IdbDescription.unpack( c1.pack() )
    assert c1.content == c1u.content == s1
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.IdbDescription'

def test_IdbIpv4Addr():
    addr_bytes    = [1,2,3,4]
    netmask_bytes = [5,6,7,8]
    c1  = option.IdbIpv4Addr(addr_bytes, netmask_bytes)
    packed_bytes = c1.pack()
    c1u = option.IdbIpv4Addr.unpack( packed_bytes )
    assert len( packed_bytes ) == 12    #todo add this test everywhere
    assert c1.addr_bytes    == c1u.addr_bytes    == addr_bytes
    assert c1.netmask_bytes == c1u.netmask_bytes == netmask_bytes
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.IdbIpv4Addr'

def test_IdbIpv6Addr():
    addr_bytes    = [ 11, 12, 13, 14,    15, 16, 17, 18,
                      21, 22, 23, 24,    25, 26, 27, 28 ]
    prefix_len = 65
    c1  = option.IdbIpv6Addr( addr_bytes, prefix_len )
    packed_bytes = c1.pack()
    c1u = option.IdbIpv6Addr.unpack( packed_bytes )
    assert len( packed_bytes ) == 24
    assert c1.addr_bytes    == c1u.addr_bytes   == addr_bytes
    assert c1.prefix_len    == c1u.prefix_len   == prefix_len
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.IdbIpv6Addr'

def test_IdbMacAddr():
    addr_bytes    = [ 11, 12, 13, 14, 15, 16 ]
    c1  = option.IdbMacAddr( addr_bytes )
    packed_bytes = c1.pack()
    c1u = option.IdbMacAddr.unpack( packed_bytes )
    assert len( packed_bytes ) == 12
    assert c1.addr_bytes        == c1u.addr_bytes       == addr_bytes
    assert util.classname(c1)   == util.classname(c1u)  == 'pcapng.option.IdbMacAddr'

def test_IdbEuiAddr():
    addr_bytes    = [ 11, 12, 13, 14, 15, 16, 17, 18 ]
    c1  = option.IdbEuiAddr( addr_bytes )
    packed_bytes = c1.pack()
    c1u = option.IdbEuiAddr.unpack( packed_bytes )
    assert len( packed_bytes ) == 12
    assert c1.addr_bytes        == c1u.addr_bytes       == addr_bytes
    assert util.classname(c1)   == util.classname(c1u)  == 'pcapng.option.IdbEuiAddr'

def test_IdbSpeed():
    speed = 123456789
    c1  = option.IdbSpeed( speed )
    packed_bytes = c1.pack()
    c1u = option.IdbSpeed.unpack( packed_bytes )
    assert len( packed_bytes ) == 12
    assert c1.speed             == c1u.speed            == speed
    assert util.classname(c1)   == util.classname(c1u)  == 'pcapng.option.IdbSpeed'

def test_IdbTsResol():
    power = 3;
    is_power_2 = False
    c1  = option.IdbTsResol( power, is_power_2 )
    packed_bytes = c1.pack()
    c1u = option.IdbTsResol.unpack( packed_bytes )
    assert len( packed_bytes ) == 8
    assert c1.ts_resol_power    == c1u.ts_resol_power   == power
    assert c1.is_power_2        == c1u.is_power_2       == is_power_2
    assert util.classname(c1)   == util.classname(c1u)  == 'pcapng.option.IdbTsResol'
    util.assert_rel_equal(  c1.get_ts_resolution_secs(), 0.001, digits=5 )
    util.assert_rel_equal( c1u.get_ts_resolution_secs(), 0.001, digits=5 )

    power = 5;
    is_power_2 = True
    c1  = option.IdbTsResol( power, is_power_2 )
    packed_bytes = c1.pack()
    c1u = option.IdbTsResol.unpack( packed_bytes )
    assert len( packed_bytes ) == 8
    assert c1.ts_resol_power    == c1u.ts_resol_power   == power
    assert c1.is_power_2        == c1u.is_power_2       == is_power_2
    assert util.classname(c1)   == util.classname(c1u)  == 'pcapng.option.IdbTsResol'
    util.assert_rel_equal(  c1.get_ts_resolution_secs(), (1.0/32.0), digits=5 )
    util.assert_rel_equal( c1u.get_ts_resolution_secs(), (1.0/32.0), digits=5 )

def test_IdbTZone():
    offset = 7
    c1  = option.IdbTZone( offset )
    packed_bytes = c1.pack()
    c1u = option.IdbTZone.unpack( packed_bytes )
    assert len( packed_bytes ) == 8
    assert c1.offset           == c1u.offset           == offset
    assert util.classname(c1)  == util.classname(c1u)  == 'pcapng.option.IdbTZone'

def test_IdbFilter():
    s1 = 'Natural Brown #4'
    c1  = option.IdbFilter(s1)
    c1u = option.IdbFilter.unpack( c1.pack() )
    assert c1.content == c1u.content == s1
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.IdbFilter'

def test_IdbOs():
    s1 = 'Ubuntu Xenial 16.04.1 LTS'
    c1  = option.IdbOs(s1)
    c1u = option.IdbOs.unpack( c1.pack() )
    assert c1.content == c1u.content == s1
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.IdbOs'

def test_IdbFcsLen():
    val_1 = 97
    c1  = option.IdbFcsLen(val_1)
    c1u = option.IdbFcsLen.unpack( c1.pack() )
    assert c1.fcs_len == c1u.fcs_len == val_1
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.IdbFcsLen'

def test_IdbTsOffset():
    ts_offset = 1234567
    c1  = option.IdbTsOffset( ts_offset )
    packed_bytes = c1.pack()
    c1u = option.IdbTsOffset.unpack( packed_bytes )
    assert len( packed_bytes ) == 12
    assert c1.ts_offset        == c1u.ts_offset        == ts_offset
    assert util.classname(c1)  == util.classname(c1u)  == 'pcapng.option.IdbTsOffset'

#-----------------------------------------------------------------------------
def test_EpbFlags():
    content    = to_bytes([1,2,3,4])
    c1  = option.EpbFlags(content)
    packed_bytes = c1.pack()
    c1u = option.EpbFlags.unpack( packed_bytes )
    assert len( packed_bytes ) == 8    #todo add this test everywhere
    assert c1.content         == c1u.content         == content
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.EpbFlags'

def test_EpbHash():
    content    = to_bytes( "<generic hash spec here>" )
    c1  = option.EpbHash(content)
    c1u = option.EpbHash.unpack( c1.pack() )
    assert c1.content         == c1u.content         == content
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.EpbHash'

def test_EpbDropCount():
    dropcount = 271
    c1  = option.EpbDropCount(dropcount)
    packed_bytes = c1.pack()
    c1u = option.EpbDropCount.unpack( packed_bytes )
    assert len( packed_bytes ) == 12    #todo add this test everywhere
    assert c1.dropcount       == c1u.dropcount       == dropcount
    assert util.classname(c1) == util.classname(c1u) == 'pcapng.option.EpbDropCount'



