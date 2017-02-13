"""
Constants & functions for defining PCAPNG options.

See:

http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#formatopt
"""
import struct

import pcapng.pen
import pcapng.util as util
from   pcapng.util import to_bytes

#-----------------------------------------------------------------------------
util.assert_python2()    #todo make work for python 2.7 or 3.3 ?
#-----------------------------------------------------------------------------

OPT_END_OF_OPT    =     0
OPT_END_OF_OPT    =     0xAB     #todo #debug

OPT_COMMENT       =     1

#todo need to do validation on data values & lengths
# custom options
OPT_CUSTOM_UTF8_COPYABLE        =  2988
OPT_CUSTOM_BINARY_COPYABLE      =  2989
OPT_CUSTOM_UTF8_NON_COPYABLE    = 19372
OPT_CUSTOM_BINARY_NON_COPYABLE  = 19373

#todo need to do validation on data values & lengths
# section header block options
OPT_SHB_HARDWARE  = 2
OPT_SHB_OS        = 3
OPT_SHB_USERAPPL  = 4

#todo need to do validation on data values & lengths
# interface description block options
OPT_IDB_NAME            =   2
OPT_IDB_DESCRIPTION     =   3
OPT_IDB_IPV4ADDR        =   4
OPT_IDB_IPV6ADDR        =   5
OPT_IDB_MACADDR         =   6
OPT_IDB_EUIADDR         =   7
OPT_IDB_SPEED           =   8
OPT_IDB_TSRESOL         =   9
OPT_IDB_TZONE           =  10
OPT_IDB_FILTER          =  11
OPT_IDB_OS              =  12
OPT_IDB_FCSLEN          =  13
OPT_IDB_TSOFFSET        =  14

#todo need to do validation on data values & lengths
# enhanced packet block options
OPT_EPB_FLAGS           =   2   #todo need validation fn & use it
OPT_EPB_HASH            =   3   #todo need validation fn & use it
OPT_EPB_DROPCOUNT       =   4   #todo need validation fn & use it

#todo verify all fields

#todo maybe need func to verify valid any option codes?

CUSTOM_OPTIONS = { OPT_CUSTOM_UTF8_COPYABLE,        OPT_CUSTOM_BINARY_COPYABLE,
                   OPT_CUSTOM_UTF8_NON_COPYABLE,    OPT_CUSTOM_BINARY_NON_COPYABLE }

GENERAL_OPTIONS = { OPT_COMMENT } | CUSTOM_OPTIONS

SHB_OPTIONS = GENERAL_OPTIONS | { OPT_SHB_HARDWARE, OPT_SHB_OS, OPT_SHB_USERAPPL }

IDB_OPTIONS = GENERAL_OPTIONS | {
    OPT_IDB_NAME, OPT_IDB_DESCRIPTION, OPT_IDB_IPV4ADDR, OPT_IDB_IPV6ADDR,
    OPT_IDB_MACADDR, OPT_IDB_EUIADDR, OPT_IDB_SPEED, OPT_IDB_TSRESOL,
    OPT_IDB_TZONE, OPT_IDB_FILTER, OPT_IDB_OS, OPT_IDB_FCSLEN, OPT_IDB_TSOFFSET}

EPB_OPTIONS = GENERAL_OPTIONS | { OPT_EPB_FLAGS, OPT_EPB_HASH, OPT_EPB_DROPCOUNT }

#todo check type on all fns

#todo need to do validation on data values & lengths
def assert_shb_option(option):
    "Returns true if option code is valid for a segment header block"
    assert (option.code in SHB_OPTIONS)

#todo need to do validation on data values & lengths
def assert_ifc_desc_option(option):
    "Returns true if option code is valid for a interface description block"
    assert (option.code in IDB_OPTIONS)

#todo need to do validation on data values & lengths
def assert_epb_option(option):
    "Returns true if option code is valid for a enhanced packet block"
    assert (option.code in EPB_OPTIONS)

#todo need to do validation on data values & lengths
def assert_custom_block_option(option):
    """Returns true if option code is valid for a custom block"""
    assert (option.code in CUSTOM_OPTIONS)

class Option:
    def __init__(self, code, content): #todo validate code
        self.code       = code
        self.content    = to_bytes(content)
    def to_map(self):           return util.select_keys(self.__dict__, ['code', 'content'])
    def __repr__(self):         return str( self.to_map() )
    def __eq__(self, other):    return self.to_map() == other.to_map()
    def __ne__(self, other):    return (not __eq__(self,other))

    #todo verify all fields
    def pack(self):   #todo needs test
        """Encodes an option into a bytes block."""
        #todo validate code
        data_len_orig   = len(self.content)
        data_pad        = util.block32_pad_bytes(self.content)
        packed_bytes    = struct.pack('=HH', self.code, data_len_orig) + data_pad
        return packed_bytes


# #todo add options for all

#todo need way to pack generic options: integer, string, float, object

def pack_all(opts_lst):  #todo needs test
    #todo verify all fields
    """Encodes an options from a dictionary into a bytes block."""
    util.assert_type_list(opts_lst)
    cum_result = ""
    for opt in opts_lst:
        cum_result += opt.pack()
    cum_result += Option(OPT_END_OF_OPT, 0).pack()
    return cum_result

def unpack_rolling(raw_bytes):
    #todo verify all fields
    """Given an bytes block of options, decodes and returns the first option and the remaining bytes."""
    util.assert_type_bytes(raw_bytes)
    assert 4 <= len(raw_bytes)
    (opt_code, content_len_orig) = struct.unpack( '=HH', raw_bytes[:4])
    content_len_pad = util.block32_ceil_num_bytes(content_len_orig)
    first_block_len_pad = 4 + content_len_pad
    assert first_block_len_pad <= len(raw_bytes)
    opt_bytes             = raw_bytes[ :first_block_len_pad   ]
    raw_bytes_remaining   = raw_bytes[  first_block_len_pad:  ]
    opt_content           = opt_bytes[ 4 : 4+content_len_orig ]
    option_read = Option( opt_code, opt_content )
    return ( option_read, raw_bytes_remaining )

def unpack_all(raw_bytes):
    """Decodes a block of raw bytes into a list of options."""
    util.assert_type_bytes(raw_bytes)
    util.assert_block32_length(raw_bytes)
    options = []
    while (0 < len(raw_bytes)):
        ( option, raw_bytes_remaining ) = unpack_rolling(raw_bytes)
        if option.code == OPT_END_OF_OPT:
            break
        else:
            options.append( option )
            raw_bytes = raw_bytes_remaining
    return options

def unpack_one(raw_bytes):
    #todo verify all fields
    """Given an bytes block of for one option, decodes and returns the option as a dictionary."""
    options = unpack_all(raw_bytes)
    assert 1 == len( options )
    return options[0]

#todo need to add custom options
def custom_option_value_pack( pen, content=[] ):
    """Packes the *value* of a custom option, i.e. the pair [PEN, content].
    Does not include the custom option code."""
    pcapng.pen.assert_valid_pen( pen )
    #todo use block32_bytes_pack/unpack() to avoid padding on output?
    value_packed_bytes = struct.pack('=L', pen ) + util.block32_pad_bytes( content )
    return value_packed_bytes

def custom_option_value_unpack( value_packed_bytes ):
    util.assert_type_bytes(value_packed_bytes)
    util.assert_block32_length(value_packed_bytes)
    (pen,) = struct.unpack('=L', value_packed_bytes[:4] )
    content_pad = value_packed_bytes[4:]
    pcapng.pen.assert_valid_pen( pen )
    #todo use block32_bytes_pack/unpack() to avoid padding on output?
    value_dict = { 'pen'            : pen,
                   'content_pad'    : content_pad }
    return value_dict


