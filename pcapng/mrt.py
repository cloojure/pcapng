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
NULL                        =   0       # deprecated
START                       =   1       # deprecated
DIE                         =   2       # deprecated
I_AM_DEAD                   =   3       # deprecated
PEER_DOWN                   =   4       # deprecated
BGP                         =   5       # deprecated
RIP                         =   6       # deprecated
IDRP                        =   7       # deprecated
RIPNG                       =   8       # deprecated
BGP4PLUS                    =   9       # deprecated
BGP4PLUS_01                 =  10       # deprecated
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
BGP_NULL                    = 0       # deprecated
BGP_UPDATE                  = 1       # deprecated
BGP_PREF_UPDATE             = 2       # deprecated
BGP_STATE_CHANGE            = 3       # deprecated
BGP_SYNC                    = 4       # deprecated
BGP_OPEN                    = 5       # deprecated
BGP_NOTIFY                  = 6       # deprecated
BGP_KEEPALIVE               = 7       # deprecated

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
BGP4MP_ENTRY                =  2       # deprecated
BGP4MP_SNAPSHOT             =  3       # deprecated
BGP4MP_MESSAGE_AS4          =  4
BGP4MP_STATE_CHANGE_AS4     =  5
BGP4MP_MESSAGE_LOCAL        =  6
BGP4MP_MESSAGE_AS4_LOCAL    =  7


def mrt_block_pack( mrt_type=0, mrt_subtype=0, content=[] ):
    """Creates an MRT header block."""
    time_secs = pcapng.util.curr_utc_secs()
    block_hdr = struct.pack('!LHHL', time_secs, mrt_type, mrt_subtype, len(content))
    block_bytes = block_hdr + pcapng.util.block32_pad_bytes(content)
    return block_bytes

def mrt_block_unpack( packed_bytes ):
    """Decodes an MRT header block."""
    (time_secs, mrt_type, mrt_subtype, content_length) = struct.unpack( '!LHHL', packed_bytes[0:12])
    content_pad = packed_bytes[12:]
    content = content_pad[:content_length]
    parsed = { 'time_secs'      : time_secs,
                'mrt_type'      : mrt_type,
                'mrt_subtype'   : mrt_subtype,
                'content'       : content }
    return parsed

def mrt_block_extended_pack(mrt_type=0, mrt_subtype=0, content=[]):
    """Encodes an MRT header block."""
    time_secs, time_usecs = pcapng.util.curr_utc_timetuple()
    block_hdr = struct.pack( '!LHHLL', time_secs, mrt_type, mrt_subtype, (4 + len(content)), time_usecs)
    block_bytes = block_hdr + pcapng.util.block32_pad_bytes(content)
    return block_bytes

def mrt_block_extended_unpack( packed_bytes ):
    """Decodes an MRT header block."""
    parsed = mrt_block_unpack(packed_bytes)
    usec_content = parsed['content']
    (time_usecs,) = struct.unpack( '!L', usec_content[:4] )
    content = usec_content[4:]
    parsed[ 'time_usecs' ] = time_usecs
    parsed[ 'content'    ] = content
    return parsed

def mrt_isis_block_pack( content=[] ):
    return mrt_block_pack( ISIS, 0, content )

def mrt_isis_block_unpack( packed_bytes ):
    result =  mrt_block_unpack( packed_bytes )
    assert result['mrt_type'] == ISIS
    return result

def mrt_isis_block_extended_pack( content=[] ):
    return mrt_block_extended_pack( ISIS_ET, 0, content )

def mrt_isis_block_extended_unpack( packed_bytes ):
    result =  mrt_block_extended_unpack( packed_bytes )
    assert result['mrt_type'] == ISIS_ET
    return result



# def ospfv2_block( local_ip_address, remote_ip_address, ospf_msg_content=[] ):
#     block = ( struct.pack( '!LL', local_ip_address, remote_ip_address ) +
#               pcapng.util.block32_pad_bytes( ospf_msg_content ))
#     hdr = mrt_block_pack(OSPFv2, 0, block)
#     result = hdr + block
#     return result

# peer_as_number  =
# local_as_number =
# interface_idx   =
# address_family  =
# remote_ip_address =
# local_ip_address =
# old_state
# new_state

