import pytest

import pcapng.block             as block
import pcapng.linktype          as linktype
import pcapng.mrt               as mrt
import pcapng.option            as option
from   pcapng.option            import Option
import pcapng.pen               as pen
import pcapng.util              as util
from   pcapng.util              import to_bytes

#todo make all tests more general/automated (local codec test fn)
#todo add generative testing

def test_section_header_block():
    opts = [ Option( option.OPT_SHB_HARDWARE  , "Dell" ),
             Option( option.OPT_SHB_OS        , "Ubuntu" ),
             Option( option.OPT_SHB_USERAPPL  , "IntelliJ Idea" ) ]
    shb_obj     = block.SectionHeaderBlock(opts)
    idb_bytes   = shb_obj.pack()
    shb_info    = block.SectionHeaderBlock.unpack(idb_bytes)
    util.assert_type_bytes( idb_bytes )
    util.assert_type_dict(  shb_info )
    assert shb_info[ 'block_type'       ] == 0x0A0D0D0A
    assert shb_info[ 'block_total_len'  ] == shb_info['block_total_len_end'] == len( idb_bytes )
    assert shb_info[ 'byte_order_magic' ] == 0x1A2B3C4D
    assert shb_info[ 'major_version'    ] == 1
    assert shb_info[ 'minor_version'    ] == 0
    assert shb_info[ 'section_len'      ] == -1
    assert shb_info[ 'options_lst'      ] == opts

def test_interface_desc_block():
    opts = [ Option( option.OPT_IDB_NAME        , "Carrier Pigeon" ),
             Option( option.OPT_IDB_DESCRIPTION , "don't you wish" ),
             Option( option.OPT_IDB_IPV4_ADDR   , to_bytes([192, 168, 13, 7, 255, 255, 255, 0])),
             Option( option.OPT_IDB_OS          , "NitrOS" ) ]
    idb_obj     = block.InterfaceDescBlock( linktype.LINKTYPE_ETHERNET, opts )
    idb_bytes   = idb_obj.pack()
    idb_info    = block.InterfaceDescBlock.unpack( idb_bytes )
    util.assert_type_dict( idb_info )
    assert idb_info[ 'block_type'       ] == 0x00000001
    assert idb_info[ 'block_total_len'  ] == idb_info['block_total_len_end'] == len(idb_bytes)
    assert idb_info[ 'link_type'        ] == linktype.LINKTYPE_ETHERNET
    assert idb_info[ 'reserved'         ] == 0
    assert idb_info[ 'snaplen'          ] == 0
    assert idb_info[ 'options_lst'      ] == opts

def test_simple_pkt_block():
    spb_obj   = block.SimplePacketBlock('abc')
    spb_bytes = spb_obj.pack('abc')
    spb_info  = block.SimplePacketBlock.unpack( spb_bytes )
    util.assert_type_dict( spb_info )
    assert spb_info['block_type']        == 0x00000003
    assert spb_info['block_total_len']   == 20
    assert spb_info['block_total_len']   == spb_info['block_total_len_end'] == len(spb_bytes)
    assert spb_info['block_total_len']   == 16 + spb_info['pkt_data_pad_len']
    assert spb_info['original_pkt_len']  == 3
    assert spb_info['pkt_data']          == 'abc'

def test_enhanced_pkt_block():
    def assert_epb_codec( interface_id, pkt_data, pkt_data_orig_len=None, options_lst=[] ):
        pkt_data = to_bytes( pkt_data )
        if pkt_data_orig_len is None:
            pkt_data_orig_len = len(pkt_data)   #todo does not test None or invalid val
        epb_obj   = block.EnhancedPacketBlock( interface_id, pkt_data, pkt_data_orig_len, options_lst )
        epb_bytes = epb_obj.pack()
        epb_info  = block.EnhancedPacketBlock.unpack( epb_bytes )
        assert epb_info[ 'block_type'               ] == block.BLOCK_TYPE_EPB
        assert epb_info[ 'interface_id'             ] == interface_id
        assert epb_info[ 'pkt_data_captured_len'    ] == len(pkt_data)
        assert epb_info[ 'pkt_data_orig_len'        ] == pkt_data_orig_len
        assert epb_info[ 'pkt_data'                 ] == pkt_data
        assert epb_info[ 'options_lst'              ] == options_lst

    opts = [ Option(option.OPT_EPB_FLAGS,     [13,14,15,16] ),
             Option(option.OPT_EPB_HASH,      [ 0x45, 0x6E, 0xC2, 0x17,    0x7C, 0x10, 0x1E, 0x3C,
                                                0x2E, 0x99, 0x6E, 0xC2,    0x9A, 0x3D, 0x50, 0x8E ] ),
             Option(option.OPT_EPB_DROPCOUNT, [13] ) ]

    assert_epb_codec( 1, [] )
    assert_epb_codec( 0, 'a' )
    assert_epb_codec( 1, 'a', 5 )
    assert_epb_codec( 2, 'go', 5 )
    assert_epb_codec( 2, 'go', 5, opts )
    assert_epb_codec( 3, 'ray' )
    assert_epb_codec( 4, 'Doh!', 23, opts )
    assert_epb_codec( 5, "Don't have a cow, man.", None, opts )
    for i in range(13):
        assert_epb_codec( 42, range(i), None, opts )

    with pytest.raises(AssertionError):
        assert_epb_codec( 5, "Don't have a cow, man.", 7 )
        assert_epb_codec( 5, "Don't have a cow, man.", 7, opts )

def test_custom_block():
    def assert_custom_block_packing( data_bytes ):
        opts = [Option(option.CUSTOM_STRING_COPYABLE, "O"),
                Option(option.CUSTOM_BINARY_COPYABLE, "Doh!"),
                Option(option.CUSTOM_STRING_NON_COPYABLE, "Release the hounds!"),
                Option(option.CUSTOM_BINARY_NON_COPYABLE, [1, 2, 3])]
        orig = to_bytes( data_bytes )
        unpacked = block.custom_block_unpack(
                   block.custom_block_pack(
                        block.CUSTOM_BLOCK_COPYABLE, pen.BROCADE_PEN, orig, opts ))
        assert unpacked[ 'block_type'    ] == block.CUSTOM_BLOCK_COPYABLE
        assert unpacked[ 'pen'           ] == pen.BROCADE_PEN
        assert unpacked[ 'content'       ] == orig
        assert unpacked[ 'options_lst'   ] == opts

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
        assert blk_dict[ 'content'      ] == orig

    assert_custom_mrt_isis_block_packing( '' )
    assert_custom_mrt_isis_block_packing( 'a' )
    assert_custom_mrt_isis_block_packing( 'go' )
    assert_custom_mrt_isis_block_packing( 'ray' )
    assert_custom_mrt_isis_block_packing( 'Doh!' )
    assert_custom_mrt_isis_block_packing( "Don't have a cow, man." )
    for i in range(13):
        assert_custom_mrt_isis_block_packing( range(i) )


