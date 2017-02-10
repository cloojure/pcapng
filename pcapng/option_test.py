import pytest
import struct
import pcapng.option    as option
import pcapng.pen       as pen
import pcapng.util      as util
from   pcapng.util      import to_bytes, str_to_bytes

def test_option_endofopt():
    assert (0,0) == struct.unpack( '=HH', option.option_endofopt())

def test_option_codec():
    def assert_option_codec(opt_code, opt_value):
        (res_code, res_bytes) = option.option_unpack(
                                option.option_pack(opt_code, opt_value))
        assert res_code   == opt_code
        assert res_bytes  == to_bytes(opt_value)

    #todo add tests for opt values of string, byte, short, int, float, double
    #todo add tests for opt value len up to 9999?
    assert_option_codec( 0, to_bytes( [] ))
    assert_option_codec( 1, to_bytes( [1,] ))
    assert_option_codec( 2, to_bytes( [1,2, ] ))
    assert_option_codec( 3, to_bytes( [1,2,3,] ))
    assert_option_codec( 4, to_bytes( [1,2,3,4,] ))
    assert_option_codec( 5, to_bytes( [1,2,3,4,5] ))
    assert_option_codec( 0, to_bytes( [0] ))
    assert_option_codec( 0, to_bytes( [5] ))
    assert_option_codec( 1, to_bytes( [78] ))
    assert_option_codec( 2, to_bytes( [178] ))
    assert_option_codec( 2, to_bytes( [255] ))

def test_options_codec():
    def assert_options_codec( opts_dict ):
        opts_dict_result = option.options_unpack(
                           option.options_pack(opts_dict))
        assert opts_dict_result == opts_dict
    val0 = str_to_bytes( '' )
    val1 = str_to_bytes( 'a' )
    val2 = str_to_bytes( 'Doh!' )
    assert_options_codec(  { 0:val0 } )
    assert_options_codec(  { 0:val0,
                             1:val1 } )
    assert_options_codec(  { 0:val0,
                             1:val1,
                             2:val2 } )

def test_option_comment_codec():
    def assert_comment_codec( str_val ):
        result = option.option_comment_unpack(
                 option.option_comment_pack(str_val))
        assert result == str_val
    assert_comment_codec( '' )
    assert_comment_codec( 'a' )
    assert_comment_codec( 'go' )
    assert_comment_codec( 'ray' )
    assert_comment_codec( 'Doh!' )
    assert_comment_codec( 'How do you like me now?' )

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
    opts_dict = {
        5: "five",           option.OPT_CUSTOM_UTF8_COPYABLE          : cust_val_1,
        6: "six",            option.OPT_CUSTOM_BINARY_COPYABLE        : cust_val_2,
        7: "seventy-seven",  option.OPT_CUSTOM_UTF8_NON_COPYABLE      : cust_val_3,
        8: "eight",          option.OPT_CUSTOM_BINARY_NON_COPYABLE    : cust_val_4,
        9: "9" }
    result_dict = option.options_unpack( option.options_pack( opts_dict ))
    assert opts_dict == result_dict
    assert opts_dict[ option.OPT_CUSTOM_UTF8_COPYABLE          ] == cust_val_1
    assert opts_dict[ option.OPT_CUSTOM_BINARY_COPYABLE        ] == cust_val_2
    assert opts_dict[ option.OPT_CUSTOM_UTF8_NON_COPYABLE      ] == cust_val_3
    assert opts_dict[ option.OPT_CUSTOM_BINARY_NON_COPYABLE    ] == cust_val_4
