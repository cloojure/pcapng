#!/usr/bin/python
from __future__ import print_function
import time
import sys
import pcapng.block
import pcapng.linktype
import pcapng.option
import pcapng.mrt
from   pcapng.util import to_bytes

pkt_len_min     = 13
pkt_len_max     = 27
pkt_len_curr    = -1

def get_dummy_pkt():
    global pkt_len_curr, pkt_len_min, pkt_len_max
    next_len = pkt_len_curr + 1
    if (pkt_len_min <= next_len <= pkt_len_max):
        pkt_len_curr = next_len 
    else:
        pkt_len_curr = pkt_len_min
    result = to_bytes( range( pkt_len_min, pkt_len_curr+1 ))
    return result


out_file_name = 'isis.pcapng'
print('\n')
print("Saving sample ISIS packets to file:   %s" % out_file_name)
pcap_fp = open( out_file_name, 'wb' )
pcap_fp.write( pcapng.block.SectionHeaderBlock().pack() )
for count in range(20):
    pkt_data = get_dummy_pkt()
    packed_bytes = pcapng.block.CustomMrtIsisBlock( pkt_data ).pack()
    pcap_fp.write( packed_bytes )
    time.sleep(0.1)
    print( '.', end='' )
    sys.stdout.flush()
    count -= 1
pcap_fp.close()
print('\n\n')


out_file_name = 'isis.mrt'
print("Saving sample ISIS packets to file:   %s" % out_file_name)
pcap_fp = open( out_file_name, 'wb' )
for count in range(20):
    pkt_data = get_dummy_pkt()
    packed_bytes = pcapng.mrt.mrt_isis_block_pack( pkt_data )
    pcap_fp.write( packed_bytes )
    time.sleep(0.1)
    print( '.', end='' )
    sys.stdout.flush()
    count -= 1
pcap_fp.close()
print('\n\n')
