import pytest

import pcapng.block             as block
import pcapng.linktype          as linktype
import pcapng.mrt               as mrt
import pcapng.option            as option
import pcapng.pen               as pen
import pcapng.util              as util
from   pcapng.util              import to_bytes

#todo make all tests more general/automated (local codec test fn)
#todo add generative testing

def test_section_header_block():
    opts = { option.OPT_SHB_HARDWARE  : "Dell",
             option.OPT_SHB_OS        : "Ubuntu",
             option.OPT_SHB_USERAPPL  : "IntelliJ Idea" }
    blk_str     = block.section_header_block_pack(opts)
    blk_data    = block.section_header_block_unpack(blk_str)
    util.assert_type_str( blk_str )
    util.assert_type_dict( blk_data )
    assert blk_data['block_type']           == 0x0A0D0D0A
    assert blk_data['block_total_len']      == len( blk_str )
    assert blk_data['block_total_len']      == blk_data['block_total_len_end']
    assert blk_data['byte_order_magic']     == 0x1A2B3C4D
    assert blk_data['major_version']        == 1
    assert blk_data['minor_version']        == 0
    assert blk_data['section_len']          == -1
    assert blk_data['options_dict']         == opts

def test_interface_desc_block():
    opts = {option.OPT_IDB_NAME          : "Carrier Pigeon",
            option.OPT_IDB_DESCRIPTION   : "don't you wish",
            option.OPT_IDB_IPV4ADDR      : to_bytes([192, 168, 13, 7, 255, 255, 255, 0]),
            option.OPT_IDB_OS            : "NitrOS"}
    blk_str    = block.interface_desc_block_pack(opts)
    blk_data   = block.interface_desc_block_unpack(blk_str)
    util.assert_type_str( blk_str )
    util.assert_type_dict( blk_data )
    assert blk_data['block_type']          == 0x00000001
    assert blk_data['block_total_len']     == len(blk_str)
    assert blk_data['block_total_len']     == blk_data['block_total_len_end']
    assert blk_data['link_type']           == linktype.LINKTYPE_ETHERNET
    assert blk_data['reserved']            == 0
    assert blk_data['snaplen']             == 0
    assert blk_data['options_dict']        == opts

def test_simple_pkt_block():
    blk_str   = block.simple_pkt_block_pack('abc')
    blk_data  = block.simple_pkt_block_unpack(blk_str)
    util.assert_type_str( blk_str )
    util.assert_type_dict( blk_data )
    assert blk_data['block_type']           == 0x00000003
    assert blk_data['block_total_len']      == 20
    assert blk_data['block_total_len']      == blk_data['block_total_len_end']
    assert blk_data['block_total_len']      == len(blk_str)
    assert blk_data['block_total_len']      == 16 + blk_data['pkt_data_pad_len']
    assert blk_data['original_pkt_len']     == 3
    assert blk_data['pkt_data']             == 'abc'


def test_custom_block():
    def assert_custom_block_packing( data_bytes ):
        opts = {option.OPT_CUSTOM_UTF8_COPYABLE : "O",
                option.OPT_CUSTOM_BINARY_COPYABLE : "Doh!",
                option.OPT_CUSTOM_UTF8_NON_COPYABLE : "Release the hounds!",
                option.OPT_CUSTOM_BINARY_NON_COPYABLE : to_bytes([1, 2, 3])}
        orig = to_bytes( data_bytes )
        unpacked = block.custom_block_unpack(
            block.custom_block_pack(
                block.CUSTOM_BLOCK_COPYABLE, pen.BROCADE_PEN, orig, opts ))
        assert unpacked[ 'block_type'    ] == block.CUSTOM_BLOCK_COPYABLE
        assert unpacked[ 'pen'           ] == pen.BROCADE_PEN
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
        blk_dict = block.custom_mrt_isis_block_unpack(
                   block.custom_mrt_isis_block_pack( orig ))
        assert blk_dict[ 'mrt_type'     ] == mrt.ISIS
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


def test_enhanced_pkt_block():
    def assert_enhanced_pkt_block_packing( interface_id, pkt_data, pkt_data_orig_len=None, options_dict={} ):
        pkt_data = to_bytes( pkt_data )
        if pkt_data_orig_len == None:
            pkt_data_orig_len = len(pkt_data)   #todo does not test None or invalid val
        blk_dict = block.enhanced_pkt_block_unpack(
                   block.enhanced_pkt_block_pack( interface_id, pkt_data, pkt_data_orig_len, options_dict ))
        assert blk_dict[ 'block_type'               ] == block.BLOCK_TYPE_EPB
        assert blk_dict[ 'interface_id'             ] == interface_id
        assert blk_dict[ 'pkt_data_captured_len'    ] == len(pkt_data)
        assert blk_dict[ 'pkt_data_orig_len'        ] == pkt_data_orig_len
        assert blk_dict[ 'pkt_data'                 ] == pkt_data
        assert blk_dict[ 'options_dict'             ] == options_dict

    opts = { option.OPT_EPB_FLAGS         : to_bytes( [13,14,15,16] ),
             option.OPT_EPB_HASH          : to_bytes( [ 0x45, 0x6E, 0xC2, 0x17,    0x7C, 0x10, 0x1E, 0x3C,
                                                        0x2E, 0x99, 0x6E, 0xC2,    0x9A, 0x3D, 0x50, 0x8E ] ),
             option.OPT_EPB_DROPCOUNT     : to_bytes( [13] ) }

    assert_enhanced_pkt_block_packing( 1, [] )
    assert_enhanced_pkt_block_packing( 0, 'a' )
    assert_enhanced_pkt_block_packing( 1, 'a', 5 )
    assert_enhanced_pkt_block_packing( 2, 'go', 5 )
    assert_enhanced_pkt_block_packing( 2, 'go', 5, opts )
    assert_enhanced_pkt_block_packing( 3, 'ray' )
    assert_enhanced_pkt_block_packing( 4, 'Doh!', 23, opts )
    assert_enhanced_pkt_block_packing( 5, "Don't have a cow, man.", None, opts )
    for i in range(13):
        assert_enhanced_pkt_block_packing( 42, range(i), None, opts )

    with pytest.raises(AssertionError): assert_enhanced_pkt_block_packing( 5, "Don't have a cow, man.", 7 )
    with pytest.raises(AssertionError): assert_enhanced_pkt_block_packing( 5, "Don't have a cow, man.", 7, opts )
