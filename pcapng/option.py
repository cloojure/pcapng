"""
Constants & functions for defining PCAPNG options.

See:

http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#formatopt
"""
import struct

import pcapng.pen   as pen
import pcapng.util  as util
from   pcapng.util  import to_bytes

#-----------------------------------------------------------------------------
util.assert_python2()    #todo make work for python 2.7 or 3.3 ?
#-----------------------------------------------------------------------------

OPT_END_OF_OPT    =     0
OPT_COMMENT       =     1
OPT_UNKNOWN       =  9999   # non-standard

#todo need to do validation on data values & lengths
# custom options
CUSTOM_STRING_COPYABLE        =  2988
CUSTOM_BINARY_COPYABLE      =  2989
CUSTOM_STRING_NON_COPYABLE    = 19372
CUSTOM_BINARY_NON_COPYABLE  = 19373

#todo need to do validation on data values & lengths
# section header block options
OPT_SHB_HARDWARE  = 2
OPT_SHB_OS        = 3
OPT_SHB_USERAPPL  = 4

#todo need to do validation on data values & lengths
#todo   make subclasses of Option
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

CUSTOM_OPTIONS = {CUSTOM_STRING_COPYABLE, CUSTOM_BINARY_COPYABLE,
                  CUSTOM_STRING_NON_COPYABLE, CUSTOM_BINARY_NON_COPYABLE}

GENERAL_OPTIONS = { OPT_COMMENT } | CUSTOM_OPTIONS

SHB_OPTIONS = GENERAL_OPTIONS | { OPT_SHB_HARDWARE, OPT_SHB_OS, OPT_SHB_USERAPPL }

IDB_OPTIONS = GENERAL_OPTIONS | {
    OPT_IDB_NAME,       OPT_IDB_DESCRIPTION,    OPT_IDB_IPV4ADDR,   OPT_IDB_IPV6ADDR,
    OPT_IDB_MACADDR,    OPT_IDB_EUIADDR,        OPT_IDB_SPEED,      OPT_IDB_TSRESOL,
    OPT_IDB_TZONE,      OPT_IDB_FILTER,         OPT_IDB_OS,         OPT_IDB_FCSLEN,
    OPT_IDB_TSOFFSET }

EPB_OPTIONS = GENERAL_OPTIONS | { OPT_EPB_FLAGS, OPT_EPB_HASH, OPT_EPB_DROPCOUNT }

ALL_OPTIONS = CUSTOM_OPTIONS | GENERAL_OPTIONS | SHB_OPTIONS | IDB_OPTIONS | EPB_OPTIONS

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

#todo verify all fields
class Option:
    def __init__(self, code, content, code_verify_disable=False):
        """Creates an Option with the specified option code & content."""
        if not code_verify_disable:
            assert (code in ALL_OPTIONS)
        self.code       = code
        self.content    = to_bytes(content)

    END_OF_OPT_BYTES = struct.pack('=HH', OPT_END_OF_OPT, 0)

    def to_map(self):           return util.select_keys(self.__dict__, ['code', 'content'])
    def __repr__(self):         return str( self.to_map() )
    def __eq__(self, other):    return self.to_map() == other.to_map()
    def __ne__(self, other):    return (not __eq__(self,other))

    def pack(self):   #todo needs test
        """Encodes an option into a bytes block."""
        #todo validate code
        data_len_orig   = len(self.content)
        data_pad        = util.block32_pad_bytes(self.content)
        packed_bytes    = struct.pack('=HH', self.code, data_len_orig) + data_pad
        return packed_bytes

    @staticmethod
    def unpack(packed_bytes):
        """Factory method to generate an Generic or Custom Option from its packed bytes."""
        (opt_code, content_len_orig) = struct.unpack('=HH', packed_bytes[:4])
        if   opt_code == OPT_COMMENT:                   return Comment.unpack( packed_bytes )
        elif opt_code == CUSTOM_STRING_COPYABLE:        return CustomStringCopyable.unpack( packed_bytes )
        elif opt_code == CUSTOM_BINARY_COPYABLE:        return CustomBinaryCopyable.unpack( packed_bytes )
        elif opt_code == CUSTOM_STRING_NON_COPYABLE:    return CustomStringNonCopyable.unpack( packed_bytes )
        elif opt_code == CUSTOM_BINARY_NON_COPYABLE:    return CustomBinaryNonCopyable.unpack( packed_bytes )
        else:
            print( 'unpack_generic(): warning - unrecognized Option={}'.format( opt_code )) #todo log
            stripped_bytes = packed_bytes[4:]
            return Option( OPT_UNKNOWN, stripped_bytes, True )

class ShbOption(Option):
    def __init__(self, code, content, code_verify_disable=False):
        """Creates an SHB Option with the specified option code & content."""
        Option.__init__( self, code, content, code_verify_disable )

    @staticmethod
    def unpack(packed_bytes):
        """Factory method to generate an Section Header Block Option from its packed bytes."""
        (opt_code, content_len_orig) = struct.unpack('=HH', packed_bytes[:4])
        if   opt_code == OPT_SHB_HARDWARE:              return ShbHardware.unpack( packed_bytes )
        elif opt_code == OPT_SHB_OS:                    return ShbOs.unpack( packed_bytes )
        elif opt_code == OPT_SHB_USERAPPL:              return ShbUserAppl.unpack( packed_bytes )
        else:
            print( 'unpack_shb(): warning - unrecognized Option={}'.format( opt_code ))     #todo log
            stripped_bytes = packed_bytes[4:]
            return ShbOption(OPT_UNKNOWN, stripped_bytes, True)


class IdbOption(Option):
    def __init__(self, code, content, code_verify_disable=False):
        """Creates an IDB Option with the specified option code & content."""
        Option.__init__( self, code, content, code_verify_disable )

    @staticmethod
    def unpack(packed_bytes):
        """Factory method to generate an Interface Desc Block Option from its packed bytes."""
        (opt_code, content_len_orig) = struct.unpack('=HH', packed_bytes[:4])
        if   opt_code == OPT_IDB_NAME:                  return IdbName.unpack( packed_bytes )
        elif opt_code == OPT_IDB_DESCRIPTION:           return IdbDescription.unpack( packed_bytes )
        else:
            print( 'unpack_idb(): warning - unrecognized Option={}'.format( opt_code ))     #todo log
            stripped_bytes = packed_bytes[4:]
            return IdbOption( OPT_UNKNOWN, stripped_bytes, True )

class Comment(Option):
    def __init__(self, content_str):
        Option.__init__(self, OPT_COMMENT, content_str)
    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return Comment(content)

class CustomStringCopyable(Option):
    def __init__(self, pen_val, content):
        pen.assert_valid_pen(pen_val)
        self.code       = CUSTOM_STRING_COPYABLE
        self.pen_val    = pen_val
        self.content    = to_bytes(content)
    def pack(self):
        content_len     = len(self.content)
        spec_len        = content_len + 4   # spec definition of length includes PEN
        content_pad     = util.block32_pad_bytes(self.content)
        packed_bytes    = struct.pack( '=HHL', self.code, spec_len, self.pen_val ) + content_pad
        return packed_bytes
    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, spec_len, pen_val) = struct.unpack('=HHL', packed_bytes[:8])
        content_len     = spec_len - 4
        content_pad     = packed_bytes[8:]
        content         = content_pad[:content_len]
        return CustomStringCopyable( pen_val, content )

class CustomBinaryCopyable(Option):
    def __init__(self, pen_val, content):
        pen.assert_valid_pen(pen_val)
        self.code       = CUSTOM_BINARY_COPYABLE
        self.pen_val    = pen_val
        self.content    = to_bytes(content)
    def pack(self):
        content_len     = len(self.content)
        spec_len        = content_len + 4   # spec definition of length includes PEN
        content_pad     = util.block32_pad_bytes(self.content)
        packed_bytes    = struct.pack( '=HHL', self.code, spec_len, self.pen_val ) + content_pad
        return packed_bytes
    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, spec_len, pen_val) = struct.unpack('=HHL', packed_bytes[:8])
        content_len     = spec_len - 4
        content_pad     = packed_bytes[8:]
        content         = content_pad[:content_len]
        return CustomBinaryCopyable( pen_val, content )

class CustomStringNonCopyable(Option):
    def __init__(self, pen_val, content):
        pen.assert_valid_pen(pen_val)
        self.code       = CUSTOM_STRING_NON_COPYABLE
        self.pen_val    = pen_val
        self.content    = to_bytes(content)
    def pack(self):
        content_len     = len(self.content)
        spec_len        = content_len + 4   # spec definition of length includes PEN
        content_pad     = util.block32_pad_bytes(self.content)
        packed_bytes    = struct.pack( '=HHL', self.code, spec_len, self.pen_val ) + content_pad
        return packed_bytes
    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, spec_len, pen_val) = struct.unpack('=HHL', packed_bytes[:8])
        content_len     = spec_len - 4
        content_pad     = packed_bytes[8:]
        content         = content_pad[:content_len]
        return CustomStringNonCopyable( pen_val, content )

class CustomBinaryNonCopyable(Option):
    def __init__(self, pen_val, content):
        pen.assert_valid_pen(pen_val)
        self.code       = CUSTOM_BINARY_NON_COPYABLE
        self.pen_val    = pen_val
        self.content    = to_bytes(content)
    def pack(self):
        content_len     = len(self.content)
        spec_len        = content_len + 4   # spec definition of length includes PEN
        content_pad     = util.block32_pad_bytes(self.content)
        packed_bytes    = struct.pack( '=HHL', self.code, spec_len, self.pen_val ) + content_pad
        return packed_bytes
    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, spec_len, pen_val) = struct.unpack('=HHL', packed_bytes[:8])
        content_len     = spec_len - 4
        content_pad     = packed_bytes[8:]
        content         = content_pad[:content_len]
        return CustomBinaryNonCopyable( pen_val, content )

#-----------------------------------------------------------------------------
class ShbHardware(ShbOption):
    def __init__(self, content_str):
        ShbOption.__init__(self, OPT_SHB_HARDWARE, content_str)
    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return ShbHardware(content)

class ShbOs(ShbOption):
    def __init__(self, content_str):
        ShbOption.__init__(self, OPT_SHB_OS, content_str)
    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return ShbOs(content)

class ShbUserAppl(ShbOption):
    def __init__(self, content_str):
        ShbOption.__init__(self, OPT_SHB_USERAPPL, content_str)
    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return ShbUserAppl(content)

#-----------------------------------------------------------------------------
class IdbName(IdbOption):
    def __init__(self, content_str):
        IdbOption.__init__(self, OPT_IDB_NAME, content_str)
    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return IdbName(content)

class IdbDescription(IdbOption):
    def __init__(self, content_str):
        IdbOption.__init__(self, OPT_IDB_DESCRIPTION, content_str)
    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return IdbDescription(content)



#todo add options for all

#todo need way to pack generic options: integer, string, float, object

def pack_all(opts_lst):  #todo needs test
    #todo verify all fields
    """Encodes an options from a dictionary into a bytes block."""
    util.assert_type_list(opts_lst)
    cum_result = ""
    for opt in opts_lst:
        cum_result += opt.pack()
    cum_result += Option.END_OF_OPT_BYTES
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
    option_read = Option( opt_code, opt_content, True )
    return ( option_read, raw_bytes_remaining )

#todo add strict string reading conformance?
    # Section 3.5 of https://pcapng.github.io/pcapng states: "Software that reads these
    # files MUST NOT assume that strings are zero-terminated, and MUST treat a
    # zero-value octet as a string terminator."   We just use th length field to read in
    # strings, and don't terminate early if there is a zero-value byte.
def unpack_all(raw_bytes):
    """Decodes a block of raw bytes into a list of options."""
    util.assert_type_bytes(raw_bytes)
    util.assert_block32_length(raw_bytes)
    print( 101, len(raw_bytes), raw_bytes)
    options = []
    while (0 < len(raw_bytes)):
        ( option, raw_bytes_remaining ) = unpack_rolling(raw_bytes)
        if option.code == OPT_END_OF_OPT:
            break
        else:
            options.append( option )
            raw_bytes = raw_bytes_remaining
    return options

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


