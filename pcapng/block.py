#todo add brocade copyright / license
#todo add header docstring to all

import struct
import pcapng.linktype          as linktype
import pcapng.mrt               as mrt
import pcapng.option            as option
from   pcapng.option            import Option
import pcapng.pen
import pcapng.util              as util
from   pcapng.util              import to_bytes

#todo think about how to handle a block of packets
#todo look at "docopt" usage -> cmdopts processing

#-----------------------------------------------------------------------------
util.assert_python2()    #todo make work for python 2.7 or 3.3 ?
#-----------------------------------------------------------------------------

BYTE_ORDER_MAGIC    = 0x1A2B3C4D

BLOCK_TYPE_EPB      = 0x00000006
BLOCK_TYPE_SHB      = 0x0A0D0D0A
BLOCK_TYPE_IDB      = 0x00000001
BLOCK_TYPE_SPB      = 0x00000003

SHB_MAJOR_VERSION   = 1
SHB_MINOR_VERSION   = 0

# For PCAPNG custom blocks
CUSTOM_BLOCK_COPYABLE    = 0x00000BAD
CUSTOM_BLOCK_NONCOPYABLE = 0x40000BAD

CUSTOM_MRT_ISIS_BLOCK_OPT = Option(option.CUSTOM_STRING_COPYABLE, 'EMBEDDED_MRT_ISIS_BLOCK')

#todo read must find mandatory SHB at beginning
    #todo global byte-order starts off undefined; is reset by each SHB
    #todo read_*_block must detect & handle any endian data (per SHB)
#todo need generic read_block(raw bytes) method
#todo need generic read_next_block(file_ptr) method
    #todo read_block_hdr(file_ptr),  block_hdr_unpack
    #todo read_block_body(file_ptr), block_body_unpack
#todo must skip any unrecognized blocks version: (major,minor) > current
#todo convert read result to object

#-----------------------------------------------------------------------------

#todo options_lst => options

#todo maybe create a SectionBlock object with SHB, IDB, options, EPBs, SPBs, etc ?

class SectionHeaderBlock:
    block_head_encoding = '=LLLHHq'     #todo need determine endian on read
    block_tail_encoding = '=L'          #todo need determine endian on read

    def __init__(self, options_lst=[]):
        util.assert_type_list(options_lst)
        for opt in options_lst:
            option.assert_shb_option(opt)
        self.options_lst = options_lst

    def pack(self):    #todo data_len
        """Encodes a section header block, including the specified options."""
        options_bytes     = option.pack_all(self.options_lst)
        section_len       = -1        #todo unused at present; must pre-accum all blocks if want to use

        block_total_len  = ( 4 +      # block type
                             4 +      # block total length
                             4 +      # byte order magic
                             2 + 2 +  # major version + minor version
                             8 +      # section length
                             len(options_bytes) +
                             4 )      # block total length
        packed_bytes = ( struct.pack( self.block_head_encoding, BLOCK_TYPE_SHB, block_total_len,
                                     BYTE_ORDER_MAGIC, SHB_MAJOR_VERSION, SHB_MINOR_VERSION, section_len) +
                         options_bytes +
                         struct.pack( self.block_tail_encoding, block_total_len ))
        return packed_bytes

    @staticmethod
    def unpack(block_bytes):      #todo verify block type & all fields
        """Decodes a bytes block into a section header block, returning a dictionary."""
        util.assert_type_bytes(block_bytes)
        ( block_type, block_total_len, byte_order_magic,
                major_version, minor_version, section_len ) = struct.unpack( SectionHeaderBlock.block_head_encoding,
                                                                                block_bytes[:24] )
        (block_total_len_end,) = struct.unpack( SectionHeaderBlock.block_tail_encoding, block_bytes[-4:])
        assert block_type       == BLOCK_TYPE_SHB
        assert byte_order_magic == BYTE_ORDER_MAGIC
        assert major_version    == SHB_MAJOR_VERSION
        assert minor_version    == SHB_MINOR_VERSION
        assert block_total_len  == block_total_len_end == len(block_bytes)
        # section_len currently ignored
        options_bytes = block_bytes[24:-4]
        options_lst  = option.unpack_all(options_bytes)  #todo verify only valid options
        shb_info = { 'block_type'          : block_type,
                     'block_total_len'     : block_total_len,
                     'byte_order_magic'    : byte_order_magic,
                     'major_version'       : major_version,
                     'minor_version'       : minor_version,
                     'section_len'         : section_len,
                     'options_lst'         : options_lst,
                     'block_total_len_end' : block_total_len_end }
        return shb_info

class InterfaceDescBlock:
    block_head_encoding = '=LLHHL'
    block_tail_encoding = '=L'

    def __init__(self, link_type=linktype.LINKTYPE_ETHERNET, #todo temp testing default
                 options_lst=[]):
        #todo need test valid linktype
        util.assert_type_list(options_lst)
        for opt in options_lst: option.assert_idb_option(opt)
        self.options_lst    = options_lst
        self.link_type      = link_type
        self.reserved       = 0    # spec req zeros
        self.snaplen        = 0    # 0 => no limit

    def pack(self):
        """Encodes an interface description block, including the specified options."""
        options_bytes   = option.pack_all( self.options_lst )
        block_total_len =   (  4 +         # block type
                               4 +         # block total length
                               2 + 2 +     # linktype + reserved
                               4 +         # snaplen
                               len(options_bytes) +
                               4 )         # block total length
        packed_bytes = ( struct.pack( self.block_head_encoding, BLOCK_TYPE_IDB,
                                      block_total_len, self.link_type, self.reserved, self.snaplen) +
                         options_bytes +
                         struct.pack( self.block_tail_encoding, block_total_len ))
        return packed_bytes

    @staticmethod
    def unpack(block_bytes):      #todo verify block type & all fields
        """Decodes a bytes block into an interface description block, returning a dictionary."""
        util.assert_type_bytes(block_bytes)
        ( block_type, block_total_len, link_type, reserved, snaplen ) = struct.unpack( InterfaceDescBlock.block_head_encoding,
                                                                                       block_bytes[:16] )
        (block_total_len_end,) = struct.unpack( InterfaceDescBlock.block_tail_encoding, block_bytes[-4:] )
        assert block_type == BLOCK_TYPE_IDB
        assert block_total_len == block_total_len_end == len(block_bytes)
        options_bytes = block_bytes[16:-4]
        options_lst = option.unpack_all(options_bytes)  #todo verify only valid options
        idb_info = { 'block_type'             : block_type,
                     'block_total_len'        : block_total_len,
                     'link_type'              : link_type,
                     'reserved'               : reserved,
                     'snaplen'                : snaplen,
                     'options_lst'            : options_lst,
                     'block_total_len_end'    : block_total_len_end }
        return idb_info

class SimplePacketBlock:
    head_encoding = '=LLL'
    tail_encoding = '=L'

    def __init__(self, pkt_data):
        self.pkt_data = to_bytes(pkt_data)        #todo is list & tuple & str ok?

    def pack(self, pkt_data):
        """Encodes a simple packet block."""
        pkt_data_pad     = util.block32_pad_bytes(self.pkt_data)
        original_pkt_len = len(self.pkt_data)
        pkt_data_pad_len = len(pkt_data_pad)
        block_total_len = ( 4 +      # block type
                            4 +      # block total length
                            4 +      # original packet length
                            pkt_data_pad_len +
                            4 )      # block total length
        block_bytes = (struct.pack(self.head_encoding, BLOCK_TYPE_SPB, block_total_len, original_pkt_len) +
                       pkt_data_pad +
                       struct.pack(self.tail_encoding, block_total_len))
        return block_bytes

    @staticmethod
    def unpack(block_bytes):      #todo verify block type & all fields
        """Decodes a bytes block into a simple packet block, returning a dictionary."""
        util.assert_type_bytes(block_bytes)
        (block_type, block_total_len, original_pkt_len) = struct.unpack( SimplePacketBlock.head_encoding, block_bytes[:12] )
        (block_total_len_end,) = struct.unpack( SimplePacketBlock.tail_encoding, block_bytes[-4:] )
        assert block_type       == BLOCK_TYPE_SPB
        assert block_total_len  == block_total_len_end
        pkt_data_pad_len    = util.block32_ceil_num_bytes(original_pkt_len)
        pkt_data            = block_bytes[12 : (12 + original_pkt_len)]  #todo clean
        spb_info =  { 'block_type'          : block_type,
                      'block_total_len'     : block_total_len,
                      'original_pkt_len'    : original_pkt_len,
                      'pkt_data_pad_len'    : pkt_data_pad_len,
                      'pkt_data'            : pkt_data,
                      'block_total_len_end' : block_total_len_end }
        return spb_info

class EnhancedPacketBlock:
    head_encoding = '=LLLLLLL'
    tail_encoding = '=L'

    def __init__(self, interface_id, pkt_data_captured, pkt_data_orig_len=None, options_lst=[]):
        util.assert_uint32( interface_id )  #todo verify args in all fns
        pkt_data_captured = to_bytes( pkt_data_captured )        #todo is list & tuple & str ok?
        if pkt_data_orig_len == None:
            pkt_data_orig_len = len(pkt_data_captured)
        else:
            util.assert_uint32(pkt_data_orig_len)
            assert len(pkt_data_captured) <= pkt_data_orig_len
        util.assert_type_list( options_lst )   #todo check type on all fns
        for opt in options_lst: option.assert_epb_option(opt)
        self.interface_id       = interface_id
        self.pkt_data_captured  = pkt_data_captured
        self.pkt_data_orig_len  = pkt_data_orig_len
        self.options_lst        = options_lst

    def pack(self):
        """Encodes a simple packet block. Default value for pkt_data_orig_len is the length
        of the supplied pkt_data."""
        #todo make all arg validation look like this (in order, at top)
        time_secs, time_usecs       = util.curr_utc_timetuple()
        pkt_data_pad                = util.block32_pad_bytes(self.pkt_data_captured)
        pkt_data_captured_len       = len(self.pkt_data_captured)
        pkt_data_captured_pad_len   = len(pkt_data_pad)
        options_bytes               = option.pack_all(self.options_lst)
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
        packed_bytes = (struct.pack( self.head_encoding, BLOCK_TYPE_EPB, block_total_len, self.interface_id,
                                     time_secs, time_usecs, pkt_data_captured_len, self.pkt_data_orig_len) +
                        pkt_data_pad +
                        options_bytes +
                        struct.pack( self.tail_encoding, block_total_len ))
        return packed_bytes

    @staticmethod
    def unpack(packed_bytes):
        """Decodes a bytes block into a simple packet block, returning a dictionary."""
        util.assert_type_bytes(packed_bytes)
        (block_type, block_total_len, interface_id, time_secs, time_usecs,
                pkt_data_captured_len, pkt_data_orig_len) = struct.unpack( EnhancedPacketBlock.head_encoding, packed_bytes[:28] )
        (block_total_len_end,) = struct.unpack( EnhancedPacketBlock.tail_encoding, packed_bytes[-4:])
        assert block_type           == BLOCK_TYPE_EPB      #todo verify block type & all fields, all fns
        assert block_total_len      == block_total_len_end == len(packed_bytes)
        assert pkt_data_captured_len <= pkt_data_orig_len

        pkt_data_captured_pad_len   = util.block32_ceil_num_bytes(pkt_data_captured_len)
        block_bytes_stripped        = packed_bytes[28:-4]
        pkt_data                    = block_bytes_stripped[:pkt_data_captured_len]
        options_bytes               = block_bytes_stripped[pkt_data_captured_pad_len:]
        options_lst                 = option.unpack_all(options_bytes)

        epb_info =  { 'block_type'              : block_type,
                      'block_total_len'         : block_total_len,
                      'interface_id'            : interface_id,
                      'time_secs'               : time_secs,
                      'time_usecs'              : time_usecs,
                      'pkt_data_captured_len'   : pkt_data_captured_len,
                      'pkt_data_orig_len'       : pkt_data_orig_len,
                      'pkt_data'                : pkt_data,
                      'options_lst'             : options_lst,
                      'block_total_len_end'     : block_total_len_end }
        return epb_info

# custom format really needs a content_length field!
def custom_block_pack(block_type, pen, content, options_lst=[]):
    """Creates an pcapng custom block."""
    assert ( (block_type == CUSTOM_BLOCK_COPYABLE) or
             (block_type == CUSTOM_BLOCK_NONCOPYABLE) )
    pcapng.pen.assert_valid_pen( pen )
    content = to_bytes(content)
    for opt in options_lst:
        option.assert_custom_block_option(opt)

    content_bytes = util.block32_bytes_pack( content )
    options_bytes = option.pack_all(options_lst)
    block_total_len = 16 + len(content_bytes) + len(options_bytes)

    packed_bytes = ( struct.pack('=LLL', block_type, block_total_len, pen ) +
                     content_bytes +
                     options_bytes +
                     struct.pack('=L', block_total_len ))
    return packed_bytes

def custom_block_unpack(block_bytes):      #todo verify block type & all fields
    """Parses an pcapng custom block."""
    util.assert_type_bytes( block_bytes )
    ( block_type, block_total_len, pen ) = struct.unpack( '=LLL', block_bytes[:12] )
    (block_total_len_end,) = struct.unpack( '=L', block_bytes[-4:] )  #todo clean
    assert ( (block_type == CUSTOM_BLOCK_COPYABLE) or
             (block_type == CUSTOM_BLOCK_NONCOPYABLE) )
    assert block_total_len == block_total_len_end == len(block_bytes)

    block_bytes_stripped = block_bytes[12:-4]
    content_bytes, options_bytes = util.block32_bytes_unpack_rolling( block_bytes_stripped )
    options_lst = option.unpack_all(options_bytes)
    parsed = { 'block_type'     : block_type,
               'pen'            : pen,
               'content'        : content_bytes,
               'options_lst'    : options_lst }
    return parsed

def custom_mrt_isis_block_pack( pkt_data ):
    "Packs ISIS MRT block into and wraps in a custom pcapnt block"
    packed_bytes = custom_block_pack( CUSTOM_BLOCK_COPYABLE, pcapng.pen.BROCADE_PEN,
                                      mrt.mrt_isis_block_pack( pkt_data ),
                                      [CUSTOM_MRT_ISIS_BLOCK_OPT])
    return packed_bytes

def custom_mrt_isis_block_unpack( block_bytes ):
    """Unpacks a mrt/isis block wrapped in a pcapng custom block."""
    util.assert_type_bytes( block_bytes )
    parsed_custom = custom_block_unpack( block_bytes )
    assert parsed_custom[ 'block_type'     ] == CUSTOM_BLOCK_COPYABLE
    assert parsed_custom[ 'pen'            ] == pcapng.pen.BROCADE_PEN
    assert parsed_custom[ 'options_lst'    ] == [CUSTOM_MRT_ISIS_BLOCK_OPT]
    parsed_mrt = mrt.mrt_isis_block_unpack( parsed_custom[ 'content' ] )
    return parsed_mrt

