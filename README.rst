Tool for reading/writing PCAPNG network packet capture files
============================================================

Alan Thompson, Brocade
athomps@brocade.com

Please see the IETF document `PCAP Next Generation (pcapng) Capture File Format <https://pcapng.github.io/pcapng/>`_

Please also see the project `home page on GitLab <https://gitlab.com/netdev-americas/pcapng/>`_
 and `at https://pypi.python.org/pypi/pcapng <https://pypi.python.org/pypi/pcapng>`_

===========
Quick Start
===========

PCAPNG files must begin with a Section Header Block::

    pcap_fp = open( 'data.pcapng', 'wb' );

    shb_opts = [ option.ShbHardware( "Dell" ),
                 option.ShbOs( "Ubuntu" ),
                 option.ShbUserAppl( "IntelliJ Idea" ) ]
    shb_obj = pcapng.block.SectionHeaderBlock( shb_opts )
    shb_packed_bytes = shb_obj.pack()
    pcap_fp.write( shb_packed_bytes )  # must be 1st block

where the options list may be omitted for this or any other block type. After the SHB, one or more
Interface Description Blocks may be included::

    idb_opts = [ option.IdbName( interface_name ),
                 option.IdbDescription( "primary interface on host" ),
                 option.IdbSpeed( 12345 ) ]
    idb_obj = pcapng.block.InterfaceDescBlock( linktype.LINKTYPE_ETHERNET, idb_opts )  # optional block
    pcap_fp.write( idb_obj.pack() )

After the SHB and any optional IDBs, one may include packet information as either Simple Packet
Blocks or Enhanced Packet Blocks::

        pkt_bytes = get_next_packet( socket_fd )
        dbg_print( pkt_bytes )
        pcap_fp.write( pcapng.block.SimplePacketBlock( pkt_bytes ).pack() )

        pkt_bytes = get_next_packet( socket_fd )
        dbg_print( pkt_bytes )

        epb_opts = [ option.EpbFlags(       [13,14,15,16] ),
                     option.EpbHash(        'just about any hash spec can go here' ),
                     option.EpbDropCount(   13 ) ]
        pcap_fp.write( pcapng.block.EnhancedPacketBlock( 0, pkt_bytes, len(pkt_bytes), epb_opts ).pack() )

Blocks may also be serialized & deserialized in bulk, as seen in the unit tests::

  def test_blocks_lst():
      blk_lst = [
          # SHB must be 1st block
          block.SectionHeaderBlock( [ option.ShbHardware( "Dell" ),
                                      option.ShbOs( "Ubuntu" ),
                                      option.ShbUserAppl( "IntelliJ Idea" ) ] ),
          block.InterfaceDescBlock( linktype.LINKTYPE_ETHERNET,
                                    [ option.IdbName( "Carrier Pigeon" ),
                                      option.IdbDescription( "Something profound here..." ),
                                      option.IdbIpv4Addr(     [192, 168, 13, 7], [255, 255, 255, 0] ),
                                      option.IdbOs( 'Ubuntu Xenial 16.04.1 LTS' ) ] ),
          block.SimplePacketBlock('abc'),
          block.EnhancedPacketBlock( 0, "<<<Stand-in for actual packet data>>>"  ),
          block.CustomBlockCopyable( pen.BROCADE_PEN, 'User-defined custom data' ),
      ]
      packed_bytes = block.pack_all( blk_lst )

      if False:
          pcap_fp = open( 'block_list.pcapng', 'wb' )
          pcap_fp.write( packed_bytes )
          pcap_fp.close()

      util.assert_block32_length( packed_bytes )
      blk_lst_unpacked = block.unpack_blocks( packed_bytes )
      assert blk_lst == blk_lst_unpacked

