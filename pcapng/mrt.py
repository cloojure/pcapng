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

# MRT types  ("_ET" suffix => Extended Timestamp field is present)
OSPFv2           = 11
TABLE_DUMP       = 12
TABLE_DUMP_V2    = 13
BGP4MP           = 16
BGP4MP_ET        = 17
ISIS             = 32
ISIS_ET          = 33
OSPFv3           = 48
OSPFv3_ET        = 49

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

