#!/usr/bin/python
import pytest
import linktype
import util
import core

def test_section_header_block():
    blk_str     = core.section_header_block_create()
    blk_data    = core.section_header_block_decode(blk_str)
    assert type( blk_str  )  == str
    assert type( blk_data )  == dict
    assert blk_data['block_type']           == 0x0A0D0D0A
    assert blk_data['block_total_len']      == 28
    assert blk_data['block_total_len']      == len( blk_str )
    assert blk_data['block_total_len']      == blk_data['block_total_len_end']
    assert blk_data['byte_order_magic']     == 0x1A2B3C4D
    assert blk_data['major_version']        == 1
    assert blk_data['minor_version']        == 0
    assert blk_data['section_len']          == -1

def test_interface_desc_block():
    blk_str    = core.interface_desc_block_create()
    blk_data   = core.interface_desc_block_decode(blk_str)
    assert type( blk_str )     == str
    assert type( blk_data )    == dict
    assert blk_data['block_type']          == 0x00000001
    assert blk_data['block_total_len']     == 20
    assert blk_data['block_total_len']     == blk_data['block_total_len_end']
    assert blk_data['block_total_len']     == len(blk_str)
    assert blk_data['link_type']           == linktype.LINKTYPE_ETHERNET
    assert blk_data['reserved']            == 0
    assert blk_data['snaplen']             == 0

def test_simple_pkt_block():
    blk_str   = core.simple_pkt_block_create( 'abc')
    blk_data  = core.simple_pkt_block_decode(blk_str)
    assert type( blk_str )                  == str
    assert type( blk_data )                 == dict
    assert blk_data['block_type']           == 0x00000003
    assert blk_data['block_tot_len']        == 20
    assert blk_data['block_tot_len']        == blk_data['block_tot_len_end']
    assert blk_data['block_tot_len']        == len(blk_str)
    assert blk_data['block_tot_len']        == 16 + blk_data['pkt_data_pad_len']
    assert blk_data['original_pkt_len']     == 3
    assert blk_data['pkt_data']             == 'abc'

