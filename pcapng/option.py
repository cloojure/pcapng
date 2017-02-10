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

SHB_OPTIONS = CUSTOM_OPTIONS | { OPT_SHB_HARDWARE, OPT_SHB_OS, OPT_SHB_USERAPPL }

IDB_OPTIONS = CUSTOM_OPTIONS | {
    OPT_IDB_NAME, OPT_IDB_DESCRIPTION, OPT_IDB_IPV4ADDR, OPT_IDB_IPV6ADDR,
    OPT_IDB_MACADDR, OPT_IDB_EUIADDR, OPT_IDB_SPEED, OPT_IDB_TSRESOL,
    OPT_IDB_TZONE, OPT_IDB_FILTER, OPT_IDB_OS, OPT_IDB_FCSLEN, OPT_IDB_TSOFFSET}

EPB_OPTIONS = CUSTOM_OPTIONS | { OPT_EPB_FLAGS, OPT_EPB_HASH, OPT_EPB_DROPCOUNT }

#todo need to do validation on data values & lengths
def assert_custom_option(opt_code):
    """Returns true if option code is valid for a custom block"""
    assert (opt_code in CUSTOM_OPTIONS)

#todo need to do validation on data values & lengths
def assert_shb_option(opt_code):
    "Returns true if option code is valid for a segment header block"
    assert (opt_code in SHB_OPTIONS)

#todo need to do validation on data values & lengths
def assert_ifc_desc_option(opt_code):
    "Returns true if option code is valid for a interface description block"
    assert (opt_code in IDB_OPTIONS)

#todo need to do validation on data values & lengths
def assert_epb_option(opt_code):
    "Returns true if option code is valid for a enhanced packet block"
    assert (opt_code in EPB_OPTIONS)


# #todo add options for all

#todo need way to pack generic options: integer, string, float, object
def option_endofopt():
    """Returns a bytes block for 'end of options' """
    result = struct.pack( '=HH', OPT_END_OF_OPT, 0 )
    return result

def option_pack(opt_code, opt_bytes):   #todo needs test
    #todo verify all fields
    """Encodes an option into a bytes block."""
    #todo validate opt_code
    util.assert_type_bytes(opt_bytes)
    data_len_orig   = len(opt_bytes)
    data_pad        = util.block32_pad_bytes(opt_bytes)
    result_hdr      = struct.pack( '=HH', opt_code, data_len_orig )
    result          = result_hdr + data_pad
    return result


def options_pack(opts_dict):  #todo needs test
    #todo verify all fields
    """Encodes an options from a dictionary into a bytes block."""
    util.assert_type_dict(opts_dict)
    cum_result = ""
    for opt_code in opts_dict.keys():
        opt_value = opts_dict[opt_code]
        opt_bytes = option_pack(opt_code, opt_value)
        cum_result += opt_bytes
    return cum_result
    #todo ***** MUST ADD { opt_endofopt : 0 }  *****


def option_unpack_rolling(opts_bytes):
    #todo verify all fields
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


def option_unpack(block_bytes):
    #todo verify all fields
    """Given an bytes block of for one option, decodes and returns the option as a dictionary."""
    opts_dict = options_unpack(block_bytes)
    assert 1 == len( opts_dict )
    opt_code  = opts_dict.keys()[0]
    opt_bytes = opts_dict[opt_code]
    return (opt_code, opt_bytes)

def option_comment_pack(comment_str):  #todo add unicode => utf-8 support
    "Encodes a string into a comment option."
    util.assert_type_str( comment_str )
    result = option_pack(OPT_COMMENT, comment_str)
    return result

def option_comment_unpack(opt_bytes):  #todo add unicode => utf-8 support
    "Decodes a comment option into a string."
    util.assert_type_bytes(opt_bytes)
    ( opt_code, opt_bytes ) = option_unpack(opt_bytes)
    assert opt_code == OPT_COMMENT
    return opt_bytes

#todo need to add custom options
def custom_option_value_pack( pen, content=[] ):
    """Packes the *value* of a custom option, i.e. the pair [PEN, content].
    Does not include the custom opiton code."""
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


