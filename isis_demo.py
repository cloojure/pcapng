#!/usr/bin/python
from __future__ import print_function
import time
import sys
import pcapng.core
import pcapng.mrt
from   pcapng.util import to_bytes

pkt_len_min     = 13
pkt_len_max     = 27
pkt_len_curr    = -1

def get_pkt():
    global pkt_len_curr, pkt_len_min, pkt_len_max
    next_len = pkt_len_curr + 1
    if (pkt_len_min <= next_len <= pkt_len_max):
        pkt_len_curr = next_len 
    else:
        pkt_len_curr = pkt_len_min
    result = to_bytes( range( pkt_len_min, pkt_len_curr+1 ))
    return result

print("Saving sample ISIS packets")
pcap_fp = open( 'isis.pcapng', 'wb' )
pcap_fp.write( pcapng.core.section_header_block_pack() )
while True:
    pkt_data = get_pkt()
    packed_bytes = pcapng.mrt.mrt_isis_block_pack( pkt_data )
    pcap_fp.write( packed_bytes )
    time.sleep(0.2)
    print( '.', end='' )
    sys.stdout.flush()