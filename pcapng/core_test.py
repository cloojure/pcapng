#!/usr/bin/env python
import struct
import pcapng.linktype
import pcapng.util
import pcapng.core

def test_option_endofopt():
    assert (0,0) == struct.unpack( '=HH', pcapng.core.option_endofopt())

def test_option_codec():
    def assert_option_codec( opt_code, opt_ByteList ):
        opt_ByteList_orig = opt_ByteList[:]  # copy data
        (res_code, res_len, res_data) = pcapng.core.option_decode(
            pcapng.core.option_encode( opt_code, opt_ByteList ))
        assert res_code     == opt_code
        assert res_len      == len( opt_ByteList )
        assert res_data     == opt_ByteList_orig

    assert_option_codec( 0, [] )
    assert_option_codec( 1, [1,] )
    assert_option_codec( 2, [1,2, ] )
    assert_option_codec( 3, [1,2,3,] )
    assert_option_codec( 4, [1,2,3,4,] )
    assert_option_codec( 5, [1,2,3,4,5] )

def test_option_comment():
    def assert_comment_codec( str_val ):
        result = pcapng.core.option_comment_decode(
                 pcapng.core.option_comment_encode(str_val))
        assert result == str_val

    assert_comment_codec( '' )
    assert_comment_codec( 'a' )
    assert_comment_codec( 'go' )
    assert_comment_codec( 'ray' )
    assert_comment_codec( 'Doh!' )
    assert_comment_codec( 'How do you like me now?' )


def test_section_header_block():
    blk_str     = pcapng.core.section_header_block_encode()
    blk_data    = pcapng.core.section_header_block_decode(blk_str)
    pcapng.util.assert_type_str( blk_str )
    pcapng.util.assert_type_dict( blk_data )
    assert blk_data['block_type']           == 0x0A0D0D0A
    assert blk_data['block_total_len']      == 28
    assert blk_data['block_total_len']      == len( blk_str )
    assert blk_data['block_total_len']      == blk_data['block_total_len_end']
    assert blk_data['byte_order_magic']     == 0x1A2B3C4D
    assert blk_data['major_version']        == 1
    assert blk_data['minor_version']        == 0
    assert blk_data['section_len']          == -1
    assert blk_data['options_dict']         == {}


def test_interface_desc_block():
    blk_str    = pcapng.core.interface_desc_block_encode()
    blk_data   = pcapng.core.interface_desc_block_decode(blk_str)
    pcapng.util.assert_type_str( blk_str )
    pcapng.util.assert_type_dict( blk_data )
    assert blk_data['block_type']          == 0x00000001
    assert blk_data['block_total_len']     == 20
    assert blk_data['block_total_len']     == blk_data['block_total_len_end']
    assert blk_data['block_total_len']     == len(blk_str)
    assert blk_data['link_type']           == pcapng.linktype.LINKTYPE_ETHERNET
    assert blk_data['reserved']            == 0
    assert blk_data['snaplen']             == 0

def test_simple_pkt_block():
    blk_str   = pcapng.core.simple_pkt_block_encode('abc')
    blk_data  = pcapng.core.simple_pkt_block_decode(blk_str)
    pcapng.util.assert_type_str( blk_str )
    pcapng.util.assert_type_dict( blk_data )
    assert blk_data['block_type']           == 0x00000003
    assert blk_data['block_tot_len']        == 20
    assert blk_data['block_tot_len']        == blk_data['block_tot_len_end']
    assert blk_data['block_tot_len']        == len(blk_str)
    assert blk_data['block_tot_len']        == 16 + blk_data['pkt_data_pad_len']
    assert blk_data['original_pkt_len']     == 3
    assert blk_data['pkt_data']             == 'abc'

