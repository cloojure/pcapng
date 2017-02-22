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
    opts = [ option.ShbHardware( "Dell" ),
             option.ShbOs( "Ubuntu" ),
             option.ShbUserAppl( "IntelliJ Idea" ) ]
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
    opts = [    option.IdbName( "Carrier Pigeon" ),
                option.IdbDescription( "don't you wish" ),
                option.IdbIpv4Addr(     [192, 168, 13, 7], [255, 255, 255, 0] ),
                option.IdbIpv6Addr(     [ 11, 12, 13, 14,    15, 16, 17, 18,
                                          21, 22, 23, 24,    25, 26, 27, 28 ], 65 ),
                option.IdbMacAddr(      [ 11, 12, 13, 14, 15, 16 ] ),
                option.IdbEuiAddr(      [ 11, 12, 13, 14, 15, 16, 17, 18 ] ),
                option.IdbSpeed( 1234567 ),
                option.IdbTsResol( 3, False ),
                option.IdbTZone( 7 ),
                option.IdbFilter( "Natural Brown #4" ),
                option.IdbOs( 'Ubuntu Xenial 16.04.1 LTS' ),
                option.IdbFcsLen( 97 ),
                option.IdbTsOffset( 314159 )
    ]
    idb_obj     = block.InterfaceDescBlock( linktype.LINKTYPE_ETHERNET, opts )
    idb_bytes   = idb_obj.pack()
    idb_info    = block.InterfaceDescBlock.unpack( idb_bytes )
    util.assert_type_dict( idb_info )
    assert idb_info[ 'block_type'       ] == 0x00000001
    assert idb_info[ 'block_total_len'  ] == idb_info['block_total_len_end'] == len(idb_bytes)
    assert idb_info[ 'link_type'        ] == linktype.LINKTYPE_ETHERNET
    assert idb_info[ 'reserved'         ] == 0
    assert idb_info[ 'snaplen'          ] == 0
    print( '251', opts )
    print( '252', idb_info[ 'options_lst' ] )
    for opt in idb_info[ 'options_lst'      ]:
        print( '253', opt )
    assert idb_info[ 'options_lst'      ] == opts

def test_simple_pkt_block():
    spb_obj   = block.SimplePacketBlock('abc')
    spb_bytes = spb_obj.pack()     #todo fix this (no var)!
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
        assert epb_info[ 'block_type'               ] == block.EnhancedPacketBlock.SPEC_CODE
        assert epb_info[ 'interface_id'             ] == interface_id
        assert epb_info[ 'pkt_data_captured_len'    ] == len(pkt_data)
        assert epb_info[ 'pkt_data_orig_len'        ] == pkt_data_orig_len
        assert epb_info[ 'pkt_data'                 ] == pkt_data
        assert epb_info[ 'options_lst'              ] == options_lst

    opts = [ option.EpbFlags(       [13,14,15,16] ),
             option.EpbHash(        'just about any hash spec can go here' ),
             option.EpbDropCount(   13 ) ]

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

def test_custom_block_copyable():
    def assert_custom_block_codec(content_bytes):
        opts = [ option.CustomStringCopyable( pen.BROCADE_PEN, "O"),
                 option.CustomBinaryCopyable( pen.BROCADE_PEN, "Doh!"),
                 option.CustomStringNonCopyable( pen.BROCADE_PEN, "Release the hounds!"),
                 option.CustomBinaryNonCopyable( pen.BROCADE_PEN, [1, 2, 3]) ]
        orig = to_bytes(content_bytes)

        cb_obj = block.CustomBlockCopyable( pen.BROCADE_PEN, orig, opts )
        cb_bytes = cb_obj.pack()
        cb_info = block.CustomBlockCopyable.unpack( cb_bytes )
        assert cb_info[ 'block_type'    ] == block.CustomBlockCopyable.SPEC_CODE
        assert cb_info[ 'pen'           ] == pen.BROCADE_PEN
        assert cb_info[ 'content'       ] == orig
        assert cb_info[ 'options_lst'   ] == opts

        cb_obj = block.CustomBlockNonCopyable( pen.BROCADE_PEN, orig, opts )
        cb_bytes = cb_obj.pack()
        cb_info = block.CustomBlockNonCopyable.unpack( cb_bytes )
        assert cb_info[ 'block_type'    ] == block.CustomBlockNonCopyable.SPEC_CODE
        assert cb_info[ 'pen'           ] == pen.BROCADE_PEN
        assert cb_info[ 'content'       ] == orig
        assert cb_info[ 'options_lst'   ] == opts



    assert_custom_block_codec( '' )
    assert_custom_block_codec( 'a' )
    assert_custom_block_codec( 'go' )
    assert_custom_block_codec( 'ray' )
    assert_custom_block_codec( 'Doh!' )
    assert_custom_block_codec( 'How do you like me now?' )
    for i in range(23):
        assert_custom_block_codec( range(i) )

def test_custom_mrt_isis_block():
    def assert_cmib_codec(content):
        content_bytes = to_bytes(content)
        cmib_obj = block.CustomMrtIsisBlock( content_bytes )
        mrt_info = block.CustomMrtIsisBlock.unpack( cmib_obj.pack() )
        assert mrt_info[ 'mrt_type'     ] == mrt.ISIS
        assert mrt_info[ 'mrt_subtype'  ] == 0
        assert mrt_info[ 'content'      ] == content_bytes

    assert_cmib_codec( '' )
    assert_cmib_codec( 'a' )
    assert_cmib_codec( 'go' )
    assert_cmib_codec( 'ray' )
    assert_cmib_codec( 'Doh!' )
    assert_cmib_codec( 'I Dream of Jeannie' )
    for i in range(13):
        assert_cmib_codec( range(i) )

#-----------------------------------------------------------------------------

def test_blocks_lst():
    if False:       #todo debug $$
        blk_lst = [
            block.SectionHeaderBlock( [ option.ShbHardware( "Dell" ),
                                        option.ShbOs( "Ubuntu" ),
                                        option.ShbUserAppl( "IntelliJ Idea" ) ] ),
            block.InterfaceDescBlock( linktype.LINKTYPE_ETHERNET,
                                      [ option.IdbName( "Carrier Pigeon" ),
                                        option.IdbDescription( "don't you wish" ),
                                        option.IdbIpv4Addr(     [192, 168, 13, 7], [255, 255, 255, 0] ),
                                        option.IdbOs( 'Ubuntu Xenial 16.04.1 LTS' ) ] ),
            block.SimplePacketBlock('abc'),
            block.EnhancedPacketBlock( 5, "Don't have a cow, man."  ),
            block.CustomBlockCopyable( pen.BROCADE_PEN, 'How do you like me now?' ),
        ]
        packed_bytes = block.pack_all( blk_lst )
        util.assert_block32_length( packed_bytes )
        blk_lst_unpacked = block.unpack_blocks( packed_bytes )
        print( 'lengths:  {}  {}'.format( len(blk_lst), len(blk_lst_unpacked)))
        for i in range( len(blk_lst)):
            blk_orig = blk_lst[i]
            blk_unpk = blk_lst_unpacked[i]
            print
            print('-------------------------------------------------------')
            print( 'blk_orig', blk_orig)
            print
            print( 'blk_unpk', blk_unpk)

        assert False
      # assert blk_lst == blk_lst_unpacked

