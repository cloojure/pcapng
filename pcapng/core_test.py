import struct
import pcapng.linktype
import pcapng.core
import pcapng.option
import pcapng.util
from pcapng.util import to_bytes, str_to_bytes


def test_option_endofopt():
    assert (0,0) == struct.unpack( '=HH', pcapng.core.option_endofopt())

def test_option_codec():
    def assert_option_codec(opt_code, opt_value):
        (res_code, res_bytes) = pcapng.core.option_unpack(
                                pcapng.core.option_pack(opt_code, opt_value))
        assert res_code   == opt_code
        assert res_bytes  == to_bytes(opt_value)

    assert_option_codec( 0, [] )
    assert_option_codec( 1, [1,] )
    assert_option_codec( 2, [1,2, ] )
    assert_option_codec( 3, [1,2,3,] )
    assert_option_codec( 4, [1,2,3,4,] )
    assert_option_codec( 5, [1,2,3,4,5] )

def test_options_codec():
    def assert_options_codec( opts_dict ):
        opts_dict_result = pcapng.core.options_unpack(
                           pcapng.core.options_pack(opts_dict))
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
        result = pcapng.core.option_comment_unpack(
                 pcapng.core.option_comment_pack(str_val))
        assert result == str_val

    assert_comment_codec( '' )
    assert_comment_codec( 'a' )
    assert_comment_codec( 'go' )
    assert_comment_codec( 'ray' )
    assert_comment_codec( 'Doh!' )
    assert_comment_codec( 'How do you like me now?' )


def test_section_header_block():
    opts = { pcapng.option.OPT_SHB_HARDWARE  : "Dell",
             pcapng.option.OPT_SHB_OS        : "Ubuntu",
             pcapng.option.OPT_SHB_USERAPPL  : "IntelliJ Idea" }
    blk_str     = pcapng.core.section_header_block_pack(opts)
    blk_data    = pcapng.core.section_header_block_unpack(blk_str)
    pcapng.util.assert_type_str( blk_str )
    pcapng.util.assert_type_dict( blk_data )
    assert blk_data['block_type']           == 0x0A0D0D0A
    assert blk_data['block_total_len']      == len( blk_str )
    assert blk_data['block_total_len']      == blk_data['block_total_len_end']
    assert blk_data['byte_order_magic']     == 0x1A2B3C4D
    assert blk_data['major_version']        == 1
    assert blk_data['minor_version']        == 0
    assert blk_data['section_len']          == -1
    assert blk_data['options_dict']         == opts

def test_interface_desc_block():
    opts = { pcapng.option.IF_NAME          : "Carrier Pigeon",
             pcapng.option.IF_DESCRIPTION   : "don't you wish",
             pcapng.option.IF_IPV4ADDR      : to_bytes( [ 192,168,13,7,  255,255,255,0 ] ),
             pcapng.option.IF_OS            : "NitrOS" }
    blk_str    = pcapng.core.interface_desc_block_pack(opts)
    blk_data   = pcapng.core.interface_desc_block_unpack(blk_str)
    pcapng.util.assert_type_str( blk_str )
    pcapng.util.assert_type_dict( blk_data )
    assert blk_data['block_type']          == 0x00000001
    assert blk_data['block_total_len']     == len(blk_str)
    assert blk_data['block_total_len']     == blk_data['block_total_len_end']
    assert blk_data['link_type']           == pcapng.linktype.LINKTYPE_ETHERNET
    assert blk_data['reserved']            == 0
    assert blk_data['snaplen']             == 0
    assert blk_data['options_dict']        == opts

def test_simple_pkt_block():
    blk_str   = pcapng.core.simple_pkt_block_pack('abc')
    blk_data  = pcapng.core.simple_pkt_block_unpack(blk_str)
    pcapng.util.assert_type_str( blk_str )
    pcapng.util.assert_type_dict( blk_data )
    assert blk_data['block_type']           == 0x00000003
    assert blk_data['block_total_len']      == 20
    assert blk_data['block_total_len']      == blk_data['block_total_len_end']
    assert blk_data['block_total_len']      == len(blk_str)
    assert blk_data['block_total_len']      == 16 + blk_data['pkt_data_pad_len']
    assert blk_data['original_pkt_len']     == 3
    assert blk_data['pkt_data']             == 'abc'


def test_custom_block():
    def assert_custom_block_packing( data_bytes ):
        opts = { pcapng.option.OPT_CUSTOM_0 : "O",
                 pcapng.option.OPT_CUSTOM_1 : "Doh!",
                 pcapng.option.OPT_CUSTOM_2 : "Release the hounds!",
                 pcapng.option.OPT_CUSTOM_3 : to_bytes( [1,2,3] ) }
        orig = to_bytes( data_bytes )
        unpacked = pcapng.core.custom_block_unpack(
            pcapng.core.custom_block_pack(
                pcapng.core.CUSTOM_BLOCK_COPYABLE, pcapng.core.BROCADE_PEN, orig, opts ))
        assert unpacked[ 'block_type'    ] == pcapng.core.CUSTOM_BLOCK_COPYABLE
        assert unpacked[ 'pen'           ] == pcapng.core.BROCADE_PEN
        assert unpacked[ 'content'       ] == orig
        assert unpacked[ 'options_dict'  ] == opts

    assert_custom_block_packing( '' )
    assert_custom_block_packing( 'a' )
    assert_custom_block_packing( 'go' )
    assert_custom_block_packing( 'ray' )
    assert_custom_block_packing( 'Doh!' )
    assert_custom_block_packing( 'How do you like me now?' )
    for i in range(23):
        assert_custom_block_packing( range(i) )

def test_custom_mrt_isis_block():
    def assert_custom_mrt_isis_block_packing( data_bytes ):
        orig = to_bytes( data_bytes )
        blk_dict = pcapng.core.custom_mrt_isis_block_unpack(
                   pcapng.core.custom_mrt_isis_block_pack( orig ))
        assert blk_dict[ 'mrt_type'     ] == pcapng.mrt.ISIS
        assert blk_dict[ 'mrt_subtype'  ] == 0
        assert blk_dict[ 'content'      ] == str(orig)

    assert_custom_mrt_isis_block_packing( '' )
    assert_custom_mrt_isis_block_packing( 'a' )
    assert_custom_mrt_isis_block_packing( 'go' )
    assert_custom_mrt_isis_block_packing( 'ray' )
    assert_custom_mrt_isis_block_packing( 'Doh!' )
    assert_custom_mrt_isis_block_packing( "Don't have a cow, man." )
    for i in range(13):
        assert_custom_mrt_isis_block_packing( range(i) )

