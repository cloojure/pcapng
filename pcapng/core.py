#todo add brocade copyright / license

#todo rename module to pcapng.block

import struct
import pcapng.linktype          as linktype
import pcapng.mrt               as mrt
import pcapng.option            as option
import pcapng.util              as util
from   pcapng.util              import to_bytes

#todo think about how to handle a block of packets
#todo look at "docopt" usage -> cmdopts processing

#-----------------------------------------------------------------------------
util.assert_python2()    #todo make work for python 2.7 or 3.3 ?
#-----------------------------------------------------------------------------

# Brocade Private Enterprise Number (PEN)
#   see:  http://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
#   Brocade Communications Systems, Inc.
#     Scott Kipp
#     skipp@brocade.com
BROCADE_PEN = 1588      #todo move to custom pcapng.pen namespace?  add other PEN values?

#todo add all block types here
BLOCK_TYPE_EPB = 0x00000006

# For PCAPNG custom blocks
CUSTOM_BLOCK_COPYABLE    = 0x00000BAD
CUSTOM_BLOCK_NONCOPYABLE = 0x40000BAD


#-----------------------------------------------------------------------------

# #todo move to pcapng.option
# #todo add options for all
def option_endofopt():
    """Returns a bytes block for 'end of options' """
    result = struct.pack( '=HH', option.OPT_END_OF_OPT, 0 )
    return result

#todo need way to pack generic options: integer, string, float, object

#todo verify all fields
def option_pack(opt_code, opt_bytes):   #todo needs test
    """Encodes an option into a bytes block."""
    #todo validate opt_code
    util.assert_type_bytes(opt_bytes)
    data_len_orig   = len(opt_bytes)
    data_pad        = util.block32_pad_bytes(opt_bytes)
    result_hdr      = struct.pack( '=HH', opt_code, data_len_orig )
    result          = result_hdr + data_pad
    return result

#todo verify all fields
def options_pack(opts_dict):  #todo needs test
    """Encodes an options from a dictionary into a bytes block."""
    util.assert_type_dict(opts_dict)
    cum_result = ""
    for opt_code in opts_dict.keys():
        opt_value = opts_dict[opt_code]
        opt_bytes = option_pack(opt_code, opt_value)
        cum_result += opt_bytes
    return cum_result
    #todo ***** MUST ADD { opt_endofopt : 0 }  *****

#todo verify all fields
def option_unpack_rolling(opts_bytes):
    """Given an bytes block of options, decodes and returns the first option and the remaining bytes."""
    util.assert_type_bytes(opts_bytes)
    assert 4 <= len(opts_bytes)
    (opt_code, data_len_orig) = struct.unpack( '=HH', opts_bytes[:4])
    #todo validate opt_code
    data_len_pad = util.block32_ceil_num_bytes(data_len_orig)
    first_block_len_pad = 4+data_len_pad
    assert first_block_len_pad <= len(opts_bytes)
    first_opt_bytes = opts_bytes[:first_block_len_pad]
    opts_bytes_remaining = opts_bytes[first_block_len_pad:]
    first_opt_value = first_opt_bytes[ 4 : 4+data_len_orig ]
    return ( opt_code, first_opt_value, opts_bytes_remaining )
    #todo make sure don't return { opt_endofopt : 0 }

#todo verify all fields
def options_unpack(opts_bytes):
    """Given an bytes block of options, decodes and returns options as a dictionary."""
    util.assert_type_bytes(opts_bytes)
    util.assert_block32_length(opts_bytes)
    cum_result_dict = {}
    while (0 < len(opts_bytes)):
        ( opt_code, opt_value, opts_bytes_remaining ) = option_unpack_rolling(opts_bytes)
        cum_result_dict[ opt_code ] = opt_value
        opts_bytes = opts_bytes_remaining
    return cum_result_dict
    #todo make sure don't return { opt_endofopt : 0 }

#todo verify all fields
def option_unpack(block_bytes):
    """Given an bytes block of for one option, decodes and returns the option as a dictionary."""
    opts_dict = options_unpack(block_bytes)
    assert 1 == len( opts_dict )
    opt_code  = opts_dict.keys()[0]
    opt_bytes = opts_dict[opt_code]
    return (opt_code, opt_bytes)

def option_comment_pack(comment_str):  #todo add unicode => utf-8 support
    "Encodes a string into a comment option."
    util.assert_type_str( comment_str )
    result = option_pack(option.OPT_COMMENT, comment_str)
    return result

def option_comment_unpack(opt_bytes):  #todo add unicode => utf-8 support
    "Decodes a comment option into a string."
    util.assert_type_bytes(opt_bytes)
    ( opt_code, opt_bytes ) = option_unpack(opt_bytes)
    assert opt_code == option.OPT_COMMENT
    return opt_bytes

#todo need to add custom options

#-----------------------------------------------------------------------------

def section_header_block_pack(options_dict={}):    #todo data_len
    """Encodes a section header block, including the specified options."""
    block_type = 0x0A0D0D0A             #todo -> const & verify on unpack
    byte_order_magic = 0x1A2B3C4D             #todo -> const & verify on unpack
    major_version = 1
    minor_version = 0
    section_len = -1        #todo set to actual (incl padding)

    for opt_code in options_dict.keys():
        option.assert_shb_option(opt_code)
    options_bytes = options_pack(options_dict)

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

def section_header_block_unpack(block_bytes):      #todo verify block type & all fields
    """Decodes a bytes block into a section header block, returning a dictionary."""
    util.assert_type_bytes(block_bytes)
    ( block_type, block_total_len, byte_order_magic, major_version,
      minor_version, section_len ) = struct.unpack( '=LlLhhq', block_bytes[:24])
    (block_total_len_end,) = struct.unpack( '=L', block_bytes[-4:])
    assert (block_total_len == block_total_len_end == len(block_bytes))  #todo simplify all 'and' & 'or'
    options_bytes = block_bytes[24:-4]
    options_dict  = options_unpack(options_bytes)  #todo verify only valid options
    parsed = { 'block_type'          : block_type ,
               'block_total_len'     : block_total_len ,
               'byte_order_magic'    : byte_order_magic ,
               'major_version'       : major_version ,
               'minor_version'       : minor_version ,
               'section_len'         : section_len ,
               'options_dict'        : options_dict,
               'block_total_len_end' : block_total_len_end }
    return parsed

def interface_desc_block_pack(options_dict={}):
    """Encodes an interface description block, including the specified options."""
    block_type = 0x00000001             #todo -> const & verify on unpack
    link_type = linktype.LINKTYPE_ETHERNET   # todo how determine?
    reserved = 0
    snaplen = 0                     # 0 => no limit

    for opt_code in options_dict.keys():
        option.assert_ifc_desc_option(opt_code)
    options_bytes = options_pack(options_dict)

    util.assert_block32_length(options_bytes)
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

def interface_desc_block_unpack(block_bytes):      #todo verify block type & all fields
    """Decodes a bytes block into an interface description block, returning a dictionary."""
    util.assert_type_bytes(block_bytes)
    ( block_type, block_total_len, link_type, reserved, snaplen ) = struct.unpack( '=LlHHl', block_bytes[:16])
    (block_total_len_end,) = struct.unpack( '=l', block_bytes[-4:])
    assert ((block_total_len == len(block_bytes)) and
            (block_total_len == block_total_len_end))
    options_bytes           = block_bytes[16:-4]
    options_dict            = options_unpack(options_bytes)  #todo verify only valid options
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
    pkt_data_pad     = util.block32_pad_bytes(pkt_data)
    block_type       = 0x00000003             #todo -> const & verify on unpack
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

def simple_pkt_block_unpack(block_bytes):      #todo verify block type & all fields
    """Decodes a bytes block into a simple packet block, returning a dictionary."""
    util.assert_type_bytes(block_bytes)
    (block_type, block_total_len, original_pkt_len) = struct.unpack( '=LLL', block_bytes[:12])
    (block_total_len_end,) = struct.unpack( '=L', block_bytes[-4:] )
    pkt_data_pad_len    = util.block32_ceil_num_bytes(original_pkt_len)
    pkt_data            = block_bytes[12 : (12 + original_pkt_len)]  #todo clean
    assert block_total_len == block_total_len_end
    parsed =    { 'block_type'          : block_type ,
                  'block_total_len'     : block_total_len ,
                  'original_pkt_len'    : original_pkt_len ,
                  'pkt_data_pad_len'    : pkt_data_pad_len ,
                  'pkt_data'            : pkt_data ,
                  'block_total_len_end' : block_total_len_end }
    return parsed

def enhanced_pkt_block_pack( interface_id, pkt_data_captured, pkt_data_orig_len=None, options_dict={} ):
    """Encodes a simple packet block. Default value for pkt_data_orig_len is the length
    of the supplied pkt_data."""
    #todo make all arg validation look like this (in order, at top)
    util.assert_uint32( interface_id )  #todo verify args in all fns
    pkt_data_captured = to_bytes( pkt_data_captured )        #todo is list & tuple & str ok?
    if pkt_data_orig_len == None:
        pkt_data_orig_len = len(pkt_data_captured)
    else:
        util.assert_uint32(pkt_data_orig_len)
        assert len(pkt_data_captured) <= pkt_data_orig_len
    util.assert_type_dict( options_dict )   #todo check type on all fns
    for opt_code in options_dict.keys():
        option.assert_shb_option(opt_code)

    time_secs, time_usecs       = util.curr_utc_timetuple()
    pkt_data_pad                = util.block32_pad_bytes(pkt_data_captured)
    pkt_data_captured_len       = len(pkt_data_captured)
    pkt_data_captured_pad_len   = len(pkt_data_pad)
    options_bytes               = options_pack(options_dict)

    block_total_len = ( 4 +      # block type
                        4 +      # block total length
                        4 +      # interface id
                        4 +      # timestamp - high
                        4 +      # timestamp - low
                        4 +      # captured packet length
                        4 +      # original packet length
                        pkt_data_captured_pad_len +
                        len(options_bytes) +
                        4 )      # block total length
    block_bytes = (struct.pack( '=LLLLLLL', BLOCK_TYPE_EPB, block_total_len, interface_id,
                                time_secs, time_usecs, pkt_data_captured_len, pkt_data_orig_len) +
                   pkt_data_pad +
                   options_bytes +
                   struct.pack( '=L', block_total_len ))
    return block_bytes

def enhanced_pkt_block_unpack(block_bytes):
    """Decodes a bytes block into a simple packet block, returning a dictionary."""
    util.assert_type_bytes(block_bytes)
    (block_type, block_total_len, interface_id, time_secs, time_usecs,
            pkt_data_captured_len, pkt_data_orig_len) = struct.unpack( '=LLLLLLL', block_bytes[:28])
    (block_total_len_end,) = struct.unpack( '=L', block_bytes[-4:])
    assert block_type == BLOCK_TYPE_EPB      #todo verify block type & all fields, all fns
    assert block_total_len == block_total_len_end == len(block_bytes)
    assert pkt_data_captured_len <= pkt_data_orig_len

    pkt_data_captured_pad_len   = util.block32_ceil_num_bytes(pkt_data_captured_len)
    block_bytes_stripped        = block_bytes[28:-4]
    pkt_data                    = block_bytes_stripped[:pkt_data_captured_len]
    options_bytes               = block_bytes_stripped[pkt_data_captured_pad_len:]
    options_dict                = options_unpack(options_bytes)

    parsed =    { 'block_type'              : block_type ,
                  'block_total_len'         : block_total_len ,
                  'interface_id'            : interface_id,
                  'time_secs'               : time_secs,
                  'time_usecs'              : time_usecs,
                  'pkt_data_captured_len'   : pkt_data_captured_len ,
                  'pkt_data_orig_len'       : pkt_data_orig_len ,
                  'pkt_data'                : pkt_data ,
                  'options_dict'            : options_dict,
                  'block_total_len_end'     : block_total_len_end }
    return parsed

# custom format really needs a content_length field!
def custom_block_pack(block_type, pen, content=[], options_dict={}):
    """Creates an pcapng custom block."""
    assert ( (block_type == CUSTOM_BLOCK_COPYABLE) or
             (block_type == CUSTOM_BLOCK_NONCOPYABLE) )
    for opt in options_dict.keys():
        assert opt in ( option.OPT_CUSTOM_0, option.OPT_CUSTOM_1,
                        option.OPT_CUSTOM_2, option.OPT_CUSTOM_3 )
    content_bytes = util.block32_bytes_pack( content )
    opt_bytes = options_pack(options_dict)
    block_total_len = 16 + len(content_bytes) + len(opt_bytes)

    packed_bytes = ( struct.pack('=LLL', block_type, block_total_len, pen ) +
                     content_bytes +
                     opt_bytes +
                     struct.pack('=L', block_total_len ))
    return packed_bytes

def custom_block_unpack(block_bytes):      #todo verify block type & all fields
    """Parses an pcapng custom block."""
    util.assert_type_bytes( block_bytes )
    ( block_type, block_total_len, pen ) = struct.unpack( '=LLL', block_bytes[:12] )
    (block_total_len_end,) = struct.unpack( '=L', block_bytes[-4:] )  #todo clean
    assert ((block_total_len == len(block_bytes)) and
            (block_total_len == block_total_len_end))

    block_bytes_stripped = block_bytes[12:-4]
    content_bytes, options_bytes = util.block32_bytes_unpack_rolling( block_bytes_stripped )
    options_dict = options_unpack(options_bytes)
    parsed = { 'block_type'     : block_type,
               'pen'            : pen,
               'content'        : content_bytes,
               'options_dict'   : options_dict }
    return parsed

def custom_mrt_isis_block_pack( pkt_data ):
    "Packs ISIS MRT block into and wraps in a custom pcapnt block"
    opts = { option.OPT_CUSTOM_0 : 'EMBEDDED_MRT_ISIS_BLOCK' }
    packed_bytes = custom_block_pack(
        CUSTOM_BLOCK_COPYABLE, BROCADE_PEN,
        mrt.mrt_isis_block_pack( pkt_data ), opts )
    return packed_bytes
    #todo need unpack;  assert 'EMBEDDED_MRT_ISIS_BLOCK'

def custom_mrt_isis_block_unpack(block_bytes):
    """Unpacks a mrt/isis block wrapped in a pcapng custom block."""
    util.assert_type_bytes( block_bytes )
    parsed_custom = custom_block_unpack( block_bytes )
    assert parsed_custom[ 'block_type'     ] == CUSTOM_BLOCK_COPYABLE
    assert parsed_custom[ 'pen'            ] == BROCADE_PEN
    assert parsed_custom[ 'options_dict'   ] == { option.OPT_CUSTOM_0 : 'EMBEDDED_MRT_ISIS_BLOCK' }
    parsed_mrt = mrt.mrt_isis_block_unpack( parsed_custom[ 'content' ] )
    return parsed_mrt
