import pytest
import struct
import pcapng.option    as option
from   pcapng.option    import Option
import pcapng.pen       as pen
import pcapng.util      as util
from   pcapng.util      import to_bytes

def test_option_codec():
    def assert_option_codec(opt_code, opt_value):
        (opt,remaining_bytes) = option.unpack_rolling( Option(opt_code, opt_value, True).pack() )
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

def test_custom_option_value():
    #todo include standalone value pack/unpack
    #todo include pack/unpack  mixed with regular options
    def assert_custom_option_value_codec( pen, content ):
        value_dict_result = option.custom_option_value_unpack(
            option.custom_option_value_pack( pen, content ))
        assert value_dict_result[ 'pen'         ] == pen
        assert value_dict_result[ 'content_pad' ] == util.block32_pad_bytes( content )
            #todo use block32_bytes_pack/unpack() to avoid padding on output?
    assert_custom_option_value_codec( pen.BROCADE_PEN, '' )
    assert_custom_option_value_codec( pen.BROCADE_PEN, 'a' )
    assert_custom_option_value_codec( pen.BROCADE_PEN, 'go' )
    assert_custom_option_value_codec( pen.BROCADE_PEN, 'ray' )
    assert_custom_option_value_codec( pen.BROCADE_PEN, 'Doh!' )
    assert_custom_option_value_codec( pen.BROCADE_PEN, 'How do you like me now?' )

    cust_val_1 = option.custom_option_value_pack( pen.BROCADE_PEN, "yo" )
    cust_val_2 = option.custom_option_value_pack( pen.BROCADE_PEN, "Mary had a little lamb" )
    cust_val_3 = option.custom_option_value_pack( pen.BROCADE_PEN, "don't copy me!" )
    cust_val_4 = option.custom_option_value_pack( pen.BROCADE_PEN, 'fin' )
    opts_lst = [
        Option( 5, "five"           ), Option( option.OPT_CUSTOM_UTF8_COPYABLE      , cust_val_1 ),
        Option( 6, "six"            ), Option( option.OPT_CUSTOM_BINARY_COPYABLE    , cust_val_2 ),
        Option( 7, "seventy-seven"  ), Option( option.OPT_CUSTOM_UTF8_NON_COPYABLE  , cust_val_3 ),
        Option( 8, "eight"          ), Option( option.OPT_CUSTOM_BINARY_NON_COPYABLE, cust_val_4 ),
        Option( 9, "9" ) ]
    result_lst = option.unpack_all( option.pack_all( opts_lst ))
    assert opts_lst == result_lst

def test_Comment():
    s1 = 'Five Stars!'
    c1 = option.Comment(s1)
    c1_unpacked = Option.unpack( c1.pack() )
    assert c1.value()           == s1
    assert c1_unpacked.value()  == s1
    assert util.class_str(c1_unpacked)  == 'Comment'

