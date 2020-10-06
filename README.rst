Tool for reading/writing PCAPNG network packet capture files
============================================================

Alan Thompson

Please see the IETF document `PCAP Next Generation
(pcapng) Capture File Format <https://pcapng.github.io/pcapng/>`_

Please also see the project `home page on GitHub <https://github.com/cloojure/pcapng.git>`_
 and `at PyPI - the Python Package Index <https://pypi.python.org/pypi/pcapng>`_

===========
Quick Start
===========

PCAPNG files must begin with a Section Header Block::

    import pcapng.block
    import pcapng.linktype
    import pcapng.option

    pcap_fp = open( 'data.pcapng', 'wb' );

    shb_opts = [ pcapng.option.ShbHardware( "Dell" ),
                 pcapng.option.ShbOs( "Ubuntu" ),
                 pcapng.option.ShbUserAppl( "IntelliJ Idea" ) ]
    shb_obj = pcapng.block.SectionHeaderBlock( shb_opts )
    shb_packed_bytes = shb_obj.pack()
    pcap_fp.write( shb_packed_bytes )  # must be 1st block

where the options list may be omitted for this or any other block type. After the SHB, one or more
Interface Description Blocks may be included::

    idb_opts = [ pcapng.option.IdbName( interface_name ),
                 pcapng.option.IdbDescription( "primary interface on host" ),
                 pcapng.option.IdbSpeed( 12345 ) ]
    idb_obj = pcapng.block.InterfaceDescBlock( linktype.LINKTYPE_ETHERNET, idb_opts )  # optional block
    pcap_fp.write( idb_obj.pack() )

After the SHB and any optional IDBs, one may include packet information as either Simple Packet
Blocks or Enhanced Packet Blocks::

        pkt_bytes = get_next_packet( socket_fd )
        dbg_print( pkt_bytes )
        pcap_fp.write( pcapng.block.SimplePacketBlock( pkt_bytes ).pack() )

        pkt_bytes = get_next_packet( socket_fd )
        dbg_print( pkt_bytes )

        epb_opts = [ pcapng.option.EpbFlags(       [13,14,15,16] ),
                     pcapng.option.EpbHash(        'just about any hash spec can go here' ),
                     pcapng.option.EpbDropCount(   13 ) ]
        pcap_fp.write( pcapng.block.EnhancedPacketBlock( 0, pkt_bytes, len(pkt_bytes), epb_opts ).pack() )

Blocks may also be serialized & deserialized in bulk, as seen in the unit tests::

  def test_blocks_lst():
      blk_lst = [
          # SHB must be 1st block
          pcapng.block.SectionHeaderBlock( [ pcapng.option.ShbHardware( "Dell" ),
                                             pcapng.option.ShbOs( "Ubuntu" ),
                                             pcapng.option.ShbUserAppl( "IntelliJ Idea" ) ] ),
          pcapng.block.InterfaceDescBlock( linktype.LINKTYPE_ETHERNET,
                                          [ pcapng.option.IdbName( "Carrier Pigeon" ),
                                            pcapng.option.IdbDescription( "Something profound here..." ),
                                            pcapng.option.IdbIpv4Addr(     [192, 168, 13, 7], [255, 255, 255, 0] ),
                                            pcapng.option.IdbOs( 'Ubuntu Xenial 16.04.1 LTS' ) ] ),
          pcapng.block.SimplePacketBlock('abc'),
          pcapng.block.EnhancedPacketBlock( 0, "<<<Stand-in for actual packet data>>>"  ),
          pcapng.block.CustomBlockCopyable( pen.BROCADE_PEN, 'User-defined custom data' ),
      ]
      packed_bytes = pcapng.block.pack_all( blk_lst )

      if False:
          pcap_fp = open( 'block_list.pcapng', 'wb' )
          pcap_fp.write( packed_bytes )
          pcap_fp.close()

      util.assert_block32_length( packed_bytes )
      blk_lst_unpacked = pcapng.block.unpack_all( packed_bytes )
      assert blk_lst == blk_lst_unpacked


Installation
============

Install from the Python Package Index (PyPI)::

    sudo pip install pcapng



Environment
===========

This project is designed to use `pipenv`, and is configured for Python 2.7

Testing
=======

    ~/gh/pcapng > pipenv shell
    Launching subshell in virtual environment…
     . /home/alan/.local/share/virtualenvs/pcapng-GhZ5R3T5/bin/activate

    (pcapng) ~/gh/pcapng > python --version     # verify Python version
    Python 2.7.18rc1

    (pcapng) ~/gh/pcapng > pytest               # execute unit tests
    ========================================================================================= test session starts =========================================================================================
    platform linux2 -- Python 2.7.18rc1, pytest-4.6.11, py-1.9.0, pluggy-0.13.1
    rootdir: /home/alan/gh/pcapng
    collected 69 items                                                                                                                                                                                    

    pcapng/block_test.py .......                                                                                                                                                                    [ 10%]
    pcapng/mrt_test.py ....                                                                                                                                                                         [ 15%]
    pcapng/option_test.py ..........................                                                                                                                                                [ 53%]
    pcapng/tlv_test.py ..........                                                                                                                                                                   [ 68%]
    pcapng/util_test.py ......................                                                                                                                                                      [100%]

    ====================================================================================== 69 passed in 0.27 seconds ======================================================================================

    (pcapng) ~/gh/pcapng > exit


API Documentation
=================

Point your browser to the included HTML documentation::

    firefox doc/pcapng/index.html         # or similar (system dependent)


Sample Programs
===============

Please see the sample programs::

    isis_agent_pcapng.py    # real-time packet capture from your machine into a PCAPNG file
    isis_demo_mrt.py        # same as above but save in Custom Block MRT format
    pcapng_timing.py        # capure 1M sample packets

The program isis_agent_pcapng.py creates an output file ``data.pcapng``, which is `viewable in
Wireshark.  <https://www.wireshark.org/>`_

The program ``isis_demo_mrt.py`` creates two output files ``isis.mrt`` & ``isis.pcapng``. The first of
thes is in raw MRT format and is not viewable by Wireshark.  For the second file, each raw MRT block
is wrapped in a PCAPNG Custom Block.  The file may be loaded successfully in Wireshark; however,
since Wireshark doesn't understand the custom format, it produces a blank display.

The third program ``pcapng_timing.py`` writes 1 million dummy packets to a PCAPNG file. A flag selects
either Simple Packet Block or Enhanced Packet Block output format.  Execution on a representative
computer yields execution times of ~6 seconds and ~16 seconds for SPB and EPB formats, respectively.


Generating Documentation 
========================

Documentation uses the ``pdoc`` tool.  Note that pdoc generates documentation from the installed
``pcapng`` package, not directly from thesource code.  To use::

    sudo pip install pdoc       # install pdoc if not present
    ./generate-docs.bash        # generate docs

Endian Convention
=================

`The PCAPNG specification <https://pcapng.github.io/pcapng/>`_ mandates that data be saved in the
native endian format of the capturing machine. This avoids the possible need for byte-swapping
during data capture, which may aid in efficiency. However, a reader of a PCAPNG file is obligated to
examine the special BYTE_ORDER_MAGIC field of the Section Header Block in order to determine the
endian convention used in generating the file.  Additionaly, since several PCAPNG files may be
concatenated together to form a larger, valid PCAPNG file, the reader must re-evaluate the endian
convention for each subsequent Section Header Block encountered.

Currently, this library does not implement endian-sensitive decoding logic, using native endian
encoding for both writing and reading. The library thus assumes that both the capturing maching and
the reading machine share the same endian conventions.  The library may be extended in the future to
implement the endian-sensitive logic for reading PCAPNG written on foreign hosts.


