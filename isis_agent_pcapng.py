#!/usr/bin/python
"""
IS_IS_FILTER
"""

from __future__ import print_function

from   bcc import BPF
import os
import struct
import sys
from   sys import argv
import socket
import pcapng.block
import pcapng.linktype as linktype
import pcapng.option as option


DEBUG_ARGS = False

#   ***** CHOOSE YOUR LOCAL INTERFACE NAME HERE *****
interface_name = "eth0"
interface_name = "wlx803f5d22051b"
interface_name = "wlp4s0"

usage_text = """
USAGE: {0} [-i <if_name>]
Try '{0} -h' for more options.
"""

help_text = """
USAGE: {0} [-i <if_name>]
optional arguments:
   -h              print this help
   -i if_name      select interface if_name. Default is eth0

examples:
    {0}            # bind socket to eth0
    {0} -i wlan0   # bind socket to wlan0
"""


def usage():
    print(usage_text.format(argv[0]))


def help():
    print(help_text.format(argv[0]))


prog = """
#include <bcc/proto.h>

struct ethernet_1_t {
  unsigned long long  dst:48;
  unsigned long long  src:48;
  unsigned int        type:16;
  unsigned int        sap:16;
} BPF_PACKET_HEADER;

#define ISISSAP  0xFEFE
#define ETHLEN 1500

int isis_filter(struct __sk_buff *skb) {

  u8 *cursor = 0;
  struct ethernet_1_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

//  if (ethernet->type <= ETHLEN && ethernet->sap == ISISSAP) {
      goto KEEP;
//  }

  goto DROP; // if no match then drop

  KEEP:
  return -1;

  DROP:
  return 0;
}
"""


def get_next_packet(socket_fd):
  return os.read(socket_fd,2048)

def dbg_print(pkt_bytes):
    if False:
        raw_list = list(pkt_bytes)
        print( 'dbg_raw_hex: len= %d' % len(raw_list) );
        hex_list = map( lambda x: x.encode("hex"), raw_list )
        hex_str = " ".join(hex_list)
        print( hex_str )
    else:
        print('.',end='')
        sys.stdout.flush()

def main():
    global interface_name

    arg1 = str(argv[1]) if 1 < len(argv) else None
    arg2 = str(argv[2]) if 2 < len(argv) else None
    no_args = (len(argv) == 1)
    one_arg = (len(argv) == 2)
    two_args = (len(argv) == 3)
    three_or_more_args = (len(argv) > 3)
    help_flag = (str(arg1) == "-h")
    interface_flag = (str(arg1) == "-i")

    if DEBUG_ARGS:
          print("arg1 = {}".format(arg1))
          print("arg2 = {}".format(arg2))
          print("no_args = {}".format(no_args))
          print("one_arg = {}".format(one_arg))
          print("two_args = {}".format(two_args))
          print("three_or_more_args = {}".format(three_or_more_args))
          print("help_flag = {}".format(help_flag))
          print("interface_flag = {}".format(interface_flag))

    if one_arg and help_flag:
          help()
          exit()

    if three_or_more_args or \
           (two_args and not interface_flag) or \
           (one_arg and not help_flag):
          usage()
          exit()

    if two_args and interface_flag:
          interface_name = argv[2]

    bpf = BPF( text=prog, debug=2 )
    is_is_filter = bpf.load_func("isis_filter", BPF.SOCKET_FILTER)

    print("binding socket to '%s'" % interface_name)
    BPF.attach_raw_socket(is_is_filter, interface_name)

    # get file descriptor of the socket previously created inside BPF.attach_raw_socket
    socket_fd = is_is_filter.sock

    #create python socket object, from the file descriptor
    sock = socket.fromfd( socket_fd, socket.AF_PACKET, socket.SOCK_RAW, 0 )
    sock.setblocking(True)

    print("Starting to listen on socket {}\n".format(interface_name))
    pcap_fp = open( 'data.pcapng', 'wb' );

    shb_opts = [ option.ShbHardware( "Dell" ),
                 option.ShbOs( "Ubuntu" ),
                 option.ShbUserAppl( "IntelliJ Idea" ) ]

    idb_opts = [ option.IdbName( interface_name ),
                 option.IdbDescription( "primary interface on host" ),
                 option.IdbSpeed( 12345 ) ]

    epb_opts = [ option.EpbFlags(       [13,14,15,16] ),
                 option.EpbHash(        'just about any hash spec can go here' ),
                 option.EpbDropCount(   13 ) ]

    pcap_fp.write( pcapng.block.SectionHeaderBlock( shb_opts ).pack() )  # must be 1st block

    idb_obj = pcapng.block.InterfaceDescBlock( linktype.LINKTYPE_ETHERNET, idb_opts )  # optional block
    idb_bytes = idb_obj.pack()
    pcap_fp.write( idb_bytes )

    count = 0
    while True:
        pkt_bytes = get_next_packet( socket_fd )
        dbg_print( pkt_bytes )

        count = count + 1
        (dummy, curr_rem) = divmod(count,2)
        if curr_rem == 0:
            pcap_fp.write( pcapng.block.SimplePacketBlock( pkt_bytes ).pack() )
        else:
            pcap_fp.write( pcapng.block.EnhancedPacketBlock( 0, pkt_bytes, len(pkt_bytes), epb_opts ).pack() )

if __name__ == "__main__":
  main()
  exit()
