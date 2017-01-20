#todo add brocade copyright / license
import struct
import pcapng.linktype
import pcapng.option
import pcapng.util
from pcapng.util import to_bytes

#todo think about how to handle a block of packets
#todo look at "docopt" usage -> cmdopts processing

#-----------------------------------------------------------------------------
pcapng.util.assert_python2()    #todo make work for python 2.7 or 3.3 ?
#-----------------------------------------------------------------------------


# IANA type codes; MRT types  ("_ET" suffix => Extended Timestamp field is present)
NULL                        =   0
START                       =   1
DIE                         =   2
I_AM_DEAD                   =   3
PEER_DOWN                   =   4
BGP                         =   5
RIP                         =   6
IDRP                        =   7
RIPNG                       =   8
BGP4PLUS                    =   9
BGP4PLUS_01                 =  10
OSPFv2                      =  11
TABLE_DUMP                  =  12
TABLE_DUMP_V2               =  13
BGP4MP                      =  16
BGP4MP_ET                   =  17
ISIS                        =  32
ISIS_ET                     =  33
OSPFv3                      =  48
OSPFv3_ET                   =  49

# IANA BGP, BGP4PLUS, and BGP4PLUS_01 Subtype Codes
BGP_NULL                    = 0
BGP_UPDATE                  = 1
BGP_PREF_UPDATE             = 2
BGP_STATE_CHANGE            = 3
BGP_SYNC                    = 4
BGP_OPEN                    = 5
BGP_NOTIFY                  = 6
BGP_KEEPALIVE               = 7

# IANA TABLE_DUMP subtypes
AFI_IPv4                    = 1
AFI_IPv6                    = 2

# IANA TABLE_DUMP_V2 subtypes
PEER_INDEX_TABLE            = 1
RIB_IPV4_UNICAST            = 2
RIB_IPV4_MULTICAST          = 3
RIB_IPV6_UNICAST            = 4
RIB_IPV6_MULTICAST          = 5
RIB_GENERIC                 = 6

# IANA BGP4MP and BGP4MP_ET Subtype Codes

BGP4MP_STATE_CHANGE         =  0
BGP4MP_MESSAGE              =  1
BGP4MP_ENTRY                =  2
BGP4MP_SNAPSHOT             =  3
BGP4MP_MESSAGE_AS4          =  4
BGP4MP_STATE_CHANGE_AS4     =  5
BGP4MP_MESSAGE_LOCAL        =  6
BGP4MP_MESSAGE_AS4_LOCAL    =  7


def section_header_block_encode(opts_dict={}):    #todo data_len
    """Encodes a section header block, including the specified options."""
    block_type = 0x0A0D0D0A
    byte_order_magic = 0x1A2B3C4D
    major_version = 1
    minor_version = 0
    section_len = -1        #todo set to actual (incl padding)

    for opt_code in opts_dict.keys():
        pcapng.option.assert_shb_option(opt_code)
    options_bytes = options_encode(opts_dict)

    block_total_len =    ( 4 +      # block type
                           4 +      # block total length
                           4 +      # byte order magic
                           2 + 2 +  # major version + minor version
                           8 +      # section length
                           len(options_bytes) +
                           4 )      # block total length
    block = ( struct.pack( '=LlLhhq', block_type, block_total_len, byte_order_magic,
                                      major_version, minor_version, section_len )
            + options_bytes
            + struct.pack( '=l', block_total_len ))
    return block

