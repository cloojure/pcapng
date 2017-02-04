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

# Brocade Private Enterprise Number (PEN)
#   see:  http://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
#   Brocade Communications Systems, Inc.
#     Scott Kipp
#     skipp@brocade.com
BROCADE_PEN = 1588

# For PCAPNG custom blocks
CUSTOM_BLOCK_COPYABLE    = 0x00000BAD
CUSTOM_BLOCK_NONCOPYABLE = 0x40000BAD


# #todo add options for all
def option_endofopt():
    """Returns a bytes block for 'end of options' """
    result = struct.pack( '=HH', pcapng.option.OPT_END_OF_OPT, 0 )
    return result

def option_pack(opt_code, opt_bytes):
    """Encodes an option into a bytes block."""
    data_len_orig   = len(opt_bytes)
    data_pad        = pcapng.util.block32_pad_bytes( to_bytes(opt_bytes))
    result_hdr      = struct.pack( '=HH', opt_code, data_len_orig )
    result          = result_hdr + data_pad
    return result

def options_pack(opts_dict):
    """Encodes an options from a dictionary into a bytes block."""
    pcapng.util.assert_type_dict(opts_dict)
    cum_result = ""
    for opt_code in opts_dict.keys():
        opt_value = opts_dict[ opt_code]
        opt_bytes = option_pack(opt_code, opt_value)
        cum_result += opt_bytes
    return cum_result

def option_unpack_rolling(opts_bytes):
    """Given an bytes block of options, decodes and returns the first option and the remaining bytes."""
    pcapng.util.assert_type_bytes(opts_bytes)
    assert 4 <= len(opts_bytes)
    (opt_code, data_len_orig) = struct.unpack( '=HH', opts_bytes[:4])
    data_len_pad = pcapng.util.block32_ceil_num_bytes(data_len_orig)
    first_block_len_pad = 4+data_len_pad
    assert first_block_len_pad <= len(opts_bytes)
    first_opt_bytes = opts_bytes[:first_block_len_pad]
    opts_bytes_remaining = opts_bytes[first_block_len_pad:]
    first_opt_value = first_opt_bytes[ 4 : 4+data_len_orig ]
    return ( opt_code, first_opt_value, opts_bytes_remaining )

def options_unpack(opts_bytes):
    """Given an bytes block of options, decodes and returns options as a dictionary."""
    pcapng.util.assert_type_bytes(opts_bytes)
    pcapng.util.assert_block32_length(opts_bytes)
    cum_result_dict = {}
    while (0 < len(opts_bytes)):
        ( opt_code, opt_value, opts_bytes_remaining ) = option_unpack_rolling(opts_bytes)
        cum_result_dict[ opt_code ] = opt_value
        opts_bytes = opts_bytes_remaining
    return cum_result_dict

def option_unpack(block_bytes):
    """Given an bytes block of for one option, decodes and returns the option as a dictionary."""
    opts_dict_result = options_unpack(block_bytes)
    assert 1 == len( opts_dict_result )
    opt_code  = opts_dict_result.keys()[0]
    opt_bytes = opts_dict_result[opt_code]
    return (opt_code, opt_bytes)

def option_comment_pack(comment_str):  #todo add unicode => utf-8 support
    "Encodes a string into a comment option."
    pcapng.util.assert_type_str( comment_str )
    result = option_pack(pcapng.option.OPT_COMMENT, comment_str)
    return result

def option_comment_unpack(opt_bytes):  #todo add unicode => utf-8 support
    "Decodes a comment option into a string."
    pcapng.util.assert_type_bytes(opt_bytes)
    ( opt_code, opt_bytes ) = option_unpack(opt_bytes)
    assert opt_code == pcapng.option.OPT_COMMENT
    return opt_bytes

def section_header_block_pack(opts_dict={}):    #todo data_len
    """Encodes a section header block, including the specified options."""
    block_type = 0x0A0D0D0A
    byte_order_magic = 0x1A2B3C4D
    major_version = 1
    minor_version = 0
    section_len = -1        #todo set to actual (incl padding)

    for opt_code in opts_dict.keys():
        pcapng.option.assert_shb_option(opt_code)
    options_bytes = options_pack(opts_dict)

    block_total_len =    ( 4 +      # block type
                           4 +      # block total length
                           4 +      # byte order magic
                           2 + 2 +  # major version + minor version
                           8 +      # section length
                           len(options_bytes) +
                           4 )      # block total length
    block_bytes = ( struct.pack( '=LlLhhq', block_type, block_total_len, byte_order_magic,
                                      major_version, minor_version, section_len ) +
                    options_bytes +
                    struct.pack( '=l', block_total_len ))
    return block_bytes

def section_header_block_unpack(block_bytes):
    """Decodes a bytes block into a section header block, returning a dictionary."""
    pcapng.util.assert_type_bytes(block_bytes)
    ( block_type, block_total_len, byte_order_magic, major_version,
      minor_version, section_len ) = struct.unpack( '=LlLhhq', block_bytes[:24])
    (block_total_len_end,) = struct.unpack( '=L', block_bytes[-4:])
    assert ((block_total_len == len(block_bytes)) and
            (block_total_len == block_total_len_end))
    options_bytes = block_bytes[24:-4]
    options_dict  = options_unpack(options_bytes)
    parsed = { 'block_type'          : block_type ,
               'block_total_len'     : block_total_len ,
               'byte_order_magic'    : byte_order_magic ,
               'major_version'       : major_version ,
               'minor_version'       : minor_version ,
               'section_len'         : section_len ,
               'options_dict'        : options_dict,
               'block_total_len_end' : block_total_len_end }
    return parsed

def interface_desc_block_pack(opts_dict={}):
    """Encodes an interface description block, including the specified options."""
    block_type = 0x00000001
    link_type = pcapng.linktype.LINKTYPE_ETHERNET   # todo how determine?
    reserved = 0
    snaplen = 0                     # 0 => no limit

    for opt_code in opts_dict.keys():
        pcapng.option.assert_if_option(opt_code)
    options_bytes = options_pack(opts_dict)

    pcapng.util.assert_block32_length(options_bytes)
    block_total_len =   (  4 +         # block type
                           4 +         # block total length
                           2 + 2 +     # linktype + reserved
                           4 +         # snaplen
                           len(options_bytes) +
                           4 )         # block total length
    block_bytes = ( struct.pack( '=LlHHl', block_type, block_total_len, link_type, reserved, snaplen ) +
                    options_bytes +
                    struct.pack( '=l', block_total_len ))
    return block_bytes

def interface_desc_block_unpack(block_bytes):
    """Decodes a bytes block into an interface description block, returning a dictionary."""
    pcapng.util.assert_type_bytes(block_bytes)
    ( block_type, block_total_len, link_type, reserved, snaplen ) = struct.unpack( '=LlHHl', block_bytes[:16])
    (block_total_len_end,) = struct.unpack( '=l', block_bytes[-4:])
    assert ((block_total_len == len(block_bytes)) and
            (block_total_len == block_total_len_end))
    options_bytes           = block_bytes[16:-4]
    options_dict            = options_unpack(options_bytes)
    parsed = { 'block_type'             : block_type ,
               'block_total_len'        : block_total_len ,
               'link_type'              : link_type ,
               'reserved'               : reserved ,
               'snaplen'                : snaplen ,
               'options_dict'           : options_dict,
               'block_total_len_end'    : block_total_len_end }
    return parsed


def simple_pkt_block_pack(pkt_data):
    """Encodes a simple packet block."""
    pkt_data         = to_bytes(pkt_data)        #todo is list & tuple & str ok?
    pkt_data_pad     = pcapng.util.block32_pad_bytes(pkt_data)
    block_type       = 0x00000003
    original_pkt_len = len(pkt_data)
    pkt_data_pad_len = len(pkt_data_pad)
    block_total_len = ( 4 +      # block type
                        4 +      # block total length
                        4 +      # original packet length
                        pkt_data_pad_len +
                        4 )      # block total length
    block_bytes = ( struct.pack( '=LLL', block_type, block_total_len, original_pkt_len ) +
                    pkt_data_pad +
                    struct.pack( '=L', block_total_len ))
    return block_bytes

def simple_pkt_block_unpack(block_bytes):
    """Decodes a bytes block into a simple packet block, returning a dictionary."""
    pcapng.util.assert_type_bytes(block_bytes)
    (block_type, block_total_len, original_pkt_len) = struct.unpack( '=LLL', block_bytes[:12])
    (block_total_len_end,) = struct.unpack( '=L', block_bytes[-4:] )
    pkt_data_pad_len    = pcapng.util.block32_ceil_num_bytes(original_pkt_len)
    pkt_data            = block_bytes[12 : (12 + original_pkt_len)]  #todo clean
    assert block_total_len == block_total_len_end
    parsed =    { 'block_type'          : block_type ,
                  'block_total_len'     : block_total_len ,
                  'original_pkt_len'    : original_pkt_len ,
                  'pkt_data_pad_len'    : pkt_data_pad_len ,
                  'pkt_data'            : pkt_data ,
                  'block_total_len_end' : block_total_len_end }
    return parsed



# custom format really needs a content_length field!
def custom_block_pack(block_type, pen, content=[], options_dict={}):
    """Creates an pcapng custom block."""
    assert ( (block_type == CUSTOM_BLOCK_COPYABLE) or
             (block_type == CUSTOM_BLOCK_NONCOPYABLE) )
    for opt in options_dict.keys():
        assert opt in ( pcapng.option.OPT_CUSTOM_0, pcapng.option.OPT_CUSTOM_1,
                        pcapng.option.OPT_CUSTOM_2, pcapng.option.OPT_CUSTOM_3 )
    content_bytes = pcapng.util.block32_bytes_pack( content )
    opt_bytes = options_pack(options_dict)
    block_total_len = 16 + len(content_bytes) + len(opt_bytes)

    packed_bytes = ( struct.pack('=LLL', block_type, block_total_len, pen ) +
                     content_bytes +
                     opt_bytes +
                     struct.pack('=L', block_total_len ))
    return packed_bytes

def custom_block_unpack(block_bytes):
    """Parses an pcapng custom block."""
    pcapng.util.assert_type_bytes( block_bytes )
    ( block_type, block_total_len, pen ) = struct.unpack( '=LLL', block_bytes[:12] )
    (block_total_len_end,) = struct.unpack( '=L', block_bytes[-4:] )  #todo clean
    assert ((block_total_len == len(block_bytes)) and
            (block_total_len == block_total_len_end))

    block_bytes_stripped = block_bytes[12:-4]
    content_bytes, options_bytes = pcapng.util.block32_bytes_unpack_rolling( block_bytes_stripped )
    options_dict = options_unpack(options_bytes)
    parsed = { 'block_type'     : block_type,
               'pen'            : pen,
               'content'        : content_bytes,
               'options_dict'   : options_dict }
    return parsed

def custom_mrt_isis_block_pack( pkt_data ):
    "Packs ISIS MRT block into and wraps in a custom pcapnt block"
    opts = { pcapng.option.OPT_CUSTOM_0 : 'EMBEDDED_MRT_ISIS_BLOCK' }
    packed_bytes = pcapng.core.custom_block_pack(
        pcapng.core.CUSTOM_BLOCK_COPYABLE, pcapng.core.BROCADE_PEN,
        pcapng.mrt.mrt_isis_block_pack( pkt_data ), opts )
    return packed_bytes
    #todo need unpack;  assert 'EMBEDDED_MRT_ISIS_BLOCK'

def custom_mrt_isis_block_unpack(block_bytes):
    """Unpacks a mrt/isis block wrapped in a pcapng custom block."""
    pcapng.util.assert_type_bytes( block_bytes )
    parsed_custom = custom_block_unpack( block_bytes )
    assert parsed_custom[ 'block_type'     ] == pcapng.core.CUSTOM_BLOCK_COPYABLE
    assert parsed_custom[ 'pen'            ] == pcapng.core.BROCADE_PEN
    assert parsed_custom[ 'options_dict'   ] == { pcapng.option.OPT_CUSTOM_0 : 'EMBEDDED_MRT_ISIS_BLOCK' }
    parsed_mrt = pcapng.mrt.mrt_isis_block_unpack( parsed_custom[ 'content' ] )
    return parsed_mrt
