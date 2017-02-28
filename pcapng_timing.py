#!/usr/bin/python

from __future__ import print_function
import sys
import pcapng.linktype      as linktype
import pcapng.block         as block
import pcapng.option        as option
import pcapng.util          as util


num_blocks = 1e6

data = 7*[None]
data[0] = util.rand_bytes(   13 )
data[1] = util.rand_bytes(  253 )
data[2] = util.rand_bytes(  453 )
data[3] = util.rand_bytes(  653 )
data[4] = util.rand_bytes(  853 )
data[5] = util.rand_bytes( 1053 )
data[6] = util.rand_bytes( 1253 )

print( "Opening output file" )
pcap_fp = open( 'data.pcapng', 'wb' );

shb_opts = [ option.ShbHardware( "Dell" ),
             option.ShbOs( "Ubuntu" ),
             option.ShbUserAppl( "IntelliJ Idea" ) ]
shb_obj = block.SectionHeaderBlock( shb_opts )
shb_packed_bytes = shb_obj.pack()
pcap_fp.write( shb_packed_bytes )  # must be 1st block

idb_opts = [ option.IdbName( "eth0" ),
             option.IdbDescription( "primary interface on host" ),
             option.IdbSpeed( 12345 ) ]
idb_obj = block.InterfaceDescBlock( linktype.LINKTYPE_ETHERNET, idb_opts )  # optional block
pcap_fp.write( idb_obj.pack() )

epb_opts = [ option.EpbFlags(       [13,14,15,16] ),
             option.EpbHash(        'just about any hash spec can go here' ),
             option.EpbDropCount(   13 ) ]

print( "Looping for {} blocks".format(num_blocks))
count = 0
data_len = len(data)
while count < num_blocks:
    curr_idx = util.mod( count, data_len )
    pkt_bytes = data[ curr_idx ]
    if True:
        pcap_fp.write( block.SimplePacketBlock( pkt_bytes ).pack() )
    else:
        pcap_fp.write( block.EnhancedPacketBlock( 0, pkt_bytes, len(pkt_bytes), epb_opts ).pack() )
    if ( util.mod( count, 1e4 ) == 0 ):
        print('.', end='')
        sys.stdout.flush()
    count = count + 1

pcap_fp.close()

print()
print( 'Finished' )

