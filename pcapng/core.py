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


def option_endofopt():
    result = struct.pack( '=HH', pcapng.option.OPT_END_OF_OPT, 0 )
    return result

# #todo add all options ability

def option_encode(opt_code, opt_bytes):
    data_len_orig   = len(opt_bytes)
    data_pad        = pcapng.util.block32_pad_bytes(to_bytes(opt_bytes))
    result_hdr      = struct.pack( '=HH', opt_code, data_len_orig )
    result          = result_hdr + data_pad
    return result

def option_decode( block ):
    pcapng.util.assert_type_bytes( block )
    (opt_code, data_len_orig) = struct.unpack( '=HH', block[0:4] )
    data_len_pad    = pcapng.util.block32_ceil_bytes(data_len_orig)
    assert (4 + data_len_pad) == len( block )
    data_bytes = block[4:]
    return ( opt_code, data_len_orig, data_bytes[ :data_len_orig ] )

#todo maybe merge these 2 fns?
def option_decode_rolling(blocks):
    pcapng.util.assert_type_str(blocks)
    assert 4 <= len(blocks)
    (opt_code, data_len_orig) = struct.unpack( '=HH', blocks[0:4])
    data_len_pad = pcapng.util.block32_ceil_bytes(data_len_orig)
    first_block_len_pad = 4+data_len_pad
    assert first_block_len_pad <= len(blocks)
    curr_block = blocks[ :first_block_len_pad ]
    blocks_remaining = blocks[ first_block_len_pad: ]
    data_str_orig = curr_block[ 4 : 4+data_len_orig ]
    return ( opt_code, data_str_orig, blocks_remaining )

def options_encode( opts ):
    pcapng.util.assert_type_dict( opts )
    cum_result = ""
    for opt_code in opts.keys():
        opt_value = opts[ opt_code ]
        opt_str = option_encode( opt_code, opt_value )
        cum_result += opt_str
    return cum_result

def options_decode( opts_str ):
    pcapng.util.assert_type_str( opts_str )
    cum_result_dict = {}
    while (0 < len(opts_str)):
        ( opt_code, data_str_orig, blocks_remaining ) = option_decode_rolling( opts_str )
        cum_result_dict[ opt_code ] = data_str_orig
        opts_str = blocks_remaining
    return cum_result_dict

def option_comment_encode( comment_str ):  #todo add unicode => utf-8 support
    pcapng.util.assert_type_str( comment_str )
    result = option_encode( pcapng.option.OPT_COMMENT, comment_str )
    return result

def option_comment_decode( block ):  #todo add unicode => utf-8 support
    pcapng.util.assert_type_str( block )
    ( opt_code, data_len_orig, data_bytes ) = option_decode( block )
    assert opt_code == pcapng.option.OPT_COMMENT
    return data_bytes

#todo: "create" -> "encode" ?
def section_header_block_encode( options_dict={} ):    #todo data_len, options
    block_type = 0x0A0D0D0A
    byte_order_magic = 0x1A2B3C4D
    major_version = 1
    minor_version = 0
    section_len = -1        #todo set to actual (incl padding)

    for opt_code in options_dict.keys():
        pcapng.option.assert_shb_option(opt_code)
    options_str = options_encode( options_dict )

    block_total_len =    ( 4 +      # block type
                           4 +      # block total length
                           4 +      # byte order magic
                           2 + 2 +  # major version + minor version
                           8 +      # section length
                           len(options_str) +
                           4 )      # block total length
    block = ( struct.pack( '=LlLhhq', block_type, block_total_len, byte_order_magic,
                                      major_version, minor_version, section_len )
            + options_str
            + struct.pack( '=l', block_total_len ))
    return block

def section_header_block_decode(block):
    assert type( block ) == str
    block_type          = pcapng.util.first( struct.unpack( '=l', block[0:4]   ))
    block_total_len     = pcapng.util.first( struct.unpack( '=l', block[4:8]   ))
    byte_order_magic    = pcapng.util.first( struct.unpack( '=L', block[8:12]  ))
    major_version       = pcapng.util.first( struct.unpack( '=h', block[12:14] ))
    minor_version       = pcapng.util.first( struct.unpack( '=h', block[14:16] ))
    section_len         = pcapng.util.first( struct.unpack( '=q', block[16:24] ))

    options_str         = block[24:-4]
    options_dict        = options_decode( options_str )

    block_total_len_end = pcapng.util.first( struct.unpack( '=l', block[-4:] ))

    block_data = {  'block_type'          : block_type ,
                    'block_total_len'     : block_total_len ,
                    'byte_order_magic'    : byte_order_magic ,
                    'major_version'       : major_version ,
                    'minor_version'       : minor_version ,
                    'section_len'         : section_len ,
                    'options_dict'        : options_dict,
                    'block_total_len_end' : block_total_len_end }
    return block_data

def interface_desc_block_encode():
    block_type = 0x00000001
    link_type = pcapng.linktype.LINKTYPE_ETHERNET   # todo how determine?
    reserved = 0
    snaplen = 0                     # 0 => no limit
    options_bytes=to_bytes( [] )                #todo none at present
    pcapng.util.assert_block32_size( options_bytes )
    block_total_len =   (  4 +         # block type
                           4 +         # block total length
                           2 + 2 +     # linktype + reserved
                           4 +         # snaplen
                           len(options_bytes) +
                           4 )         # block total length
    block = ( struct.pack( '=LlHHl', block_type, block_total_len, link_type, reserved, snaplen )
            + options_bytes
            + struct.pack( '=l', block_total_len ))
    return block

def interface_desc_block_decode(block):
    assert type( block ) == str       #todo is tuple & str ok?
    block_type              = struct.unpack( '=L', block[0:4]   )[0]
    block_total_len         = struct.unpack( '=l', block[4:8]   )[0]
    link_type               = struct.unpack( '=H', block[8:10]  )[0]
    reserved                = struct.unpack( '=H', block[10:12] )[0]
    snaplen                 = struct.unpack( '=l', block[12:16] )[0]
  # options_str  #todo
    block_total_len_end     = struct.unpack( '=l', block[-4:]   )[0]
    block_data = { 'block_type'              : block_type ,
                   'block_total_len'         : block_total_len ,
                   'link_type'               : link_type ,
                   'reserved'                : reserved ,
                   'snaplen'                 : snaplen ,
                   # options_str  #todo
                   'block_total_len_end'     : block_total_len_end }
    return block_data


def simple_pkt_block_encode(pkt_data):
    pcapng.util.assert_type_str(pkt_data)        #todo is list & tuple & str ok?
    pkt_data            = list(map(ord, pkt_data))
    pkt_data_pad        = pcapng.util.block32_pad_bytes(pkt_data)
    block_type = 0x00000003
    original_pkt_len = len(pkt_data)
    pkt_data_pad_len = len(pkt_data_pad)
    block_total_len = ( 4 +      # block type
                        4 +      # block total length
                        4 +      # original packet length
                        pkt_data_pad_len +
                        4 )      # block total length
    block = ( struct.pack( '=LLL', block_type, block_total_len, original_pkt_len ) +
              pkt_data_pad +
              struct.pack( '=L', block_total_len ))
    return block

def simple_pkt_block_decode(block):
    pcapng.util.assert_type_str( block )
    block_type          = pcapng.util.first( struct.unpack( '=L', block[0:4]  ))
    block_tot_len       = pcapng.util.first( struct.unpack( '=L', block[4:8]  ))
    original_pkt_len    = pcapng.util.first( struct.unpack( '=L', block[8:12] ))
    pkt_data_pad_len    = pcapng.util.block32_ceil_bytes(original_pkt_len)
    pkt_data            = block[ 12 : (12+original_pkt_len)  ]
    block_tot_len_end   = pcapng.util.first( struct.unpack( '=L', block[ -4:block_tot_len] ))
    block_data =    { 'block_type'          : block_type ,
                      'block_tot_len'         : block_tot_len ,
                      'original_pkt_len'    : original_pkt_len ,
                      'pkt_data_pad_len'    : pkt_data_pad_len ,
                      'pkt_data'            : pkt_data ,
                      'block_tot_len_end'     : block_tot_len_end }
    return block_data

