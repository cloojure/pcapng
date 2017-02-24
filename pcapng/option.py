# Copyright 2017 Brocade Communications Systems, Inc
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""
Constants & functions for defining PCAPNG options.

See:

http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#formatopt
"""
import struct

import pcapng.pen   as pen
import pcapng.util  as util
from   pcapng.util  import to_bytes

#todo add docstrings for all classes
#todo add docstrings for all constructurs
#todo add docstrings for all methods

#todo add strict string reading conformance?
    # Section 3.5 of https://pcapng.github.io/pcapng states: "Software that reads these
    # files MUST NOT assume that strings are zero-terminated, and MUST treat a
    # zero-value octet as a string terminator."   We just use th length field to read in
    # strings, and don't terminate early if there is a zero-value byte.


#-----------------------------------------------------------------------------
util.assert_python2()    #todo make work for python 2.7 or 3.3 ?
#-----------------------------------------------------------------------------
#todo add global statemachine/var for write (testing) and read (host dependent)
#todo -> pack.uint64_pack()/_unpack() & similar everywhere
def uint8_pack(    arg ):       return struct.pack(   '=B', arg )
def uint8_unpack(  arg ):       return struct.unpack( '=B', arg )[0]
def uint64_pack(   arg ):       return struct.pack(   '=Q', arg )
def uint64_unpack( arg ):       return struct.unpack( '=Q', arg )[0]

def  int8_pack(    arg ):       return struct.pack(   '=b', arg )
def  int8_unpack(  arg ):       return struct.unpack( '=b', arg )[0]
def  int64_pack(   arg ):       return struct.pack(   '=q', arg )
def  int64_unpack( arg ):       return struct.unpack( '=q', arg )[0]

def float32_pack(   arg ):      return struct.pack(   '=f', arg )
def float32_unpack( arg ):      return struct.unpack( '=f', arg )[0]

#-----------------------------------------------------------------------------
def strip_header( packed_bytes ): #todo use for all unpack()
    util.assert_block32_length( packed_bytes )
    (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
    content_pad = packed_bytes[4:]
    assert content_len <= len(content_pad)
    content = content_pad[:content_len]
    return (opt_code, content_len, content)

#todo use everywhere
def add_header(id_code, content_len, content):   #todo delete content var?
    content_pad = util.block32_pad_bytes( content )
    packed_bytes = struct.pack('=HH', id_code, content_len) + content_pad
    return packed_bytes

#-----------------------------------------------------------------------------
# option ID codes from PCAPNG spec

OPT_END_OF_OPT    =     0
OPT_UNKNOWN       =  9999   # non-standard

#todo need to do validation on data values & lengths
# custom options
# CUSTOM_STRING_COPYABLE      =  2988   #delete -> class def
# CUSTOM_BINARY_COPYABLE      =  2989   #delete -> class def
# CUSTOM_STRING_NON_COPYABLE  = 19372   #delete -> class def
# CUSTOM_BINARY_NON_COPYABLE  = 19373   #delete -> class def

#todo need to do validation on data values & lengths
# section header block options
# OPT_SHB_HARDWARE  = 2    #delete -> class def
# OPT_SHB_OS        = 3    #delete -> class def
# OPT_SHB_USERAPPL  = 4    #delete -> class def

#todo need to do validation on data values & lengths
#todo   make subclasses of Option
# interface description block options
# OPT_IDB_NAME            =   2    #delete -> class def
# OPT_IDB_DESCRIPTION     =   3    #delete -> class def
# OPT_IDB_IPV4_ADDR       =   4    #delete -> class def
# OPT_IDB_IPV6_ADDR       =   5   #delete -> class def
# OPT_IDB_MAC_ADDR        =   6  #delete -> class def
# OPT_IDB_EUI_ADDR        =   7  #delete -> class def
# OPT_IDB_SPEED           =   8  #delete -> class def
# OPT_IDB_TS_RESOL        =   9  #delete -> class def
# OPT_IDB_TZONE           =  10  #delete -> class def
# OPT_IDB_FILTER          =  11
# OPT_IDB_OS              =  12
# OPT_IDB_FCS_LEN         =  13
# OPT_IDB_TS_OFFSET       =  14

#todo need to do validation on data values & lengths
# enhanced packet block options
# OPT_EPB_FLAGS           =   2   #todo need validation fn & use it
# OPT_EPB_HASH            =   3   #todo need validation fn & use it
# OPT_EPB_DROPCOUNT       =   4   #todo need validation fn & use it

#todo verify all fields

#todo maybe need func to verify valid any option codes?

#todo check type on all fns

#todo need to do validation on data values & lengths

def is_end_of_opt( opt_bytes ):
    return opt_bytes == Option.END_OF_OPT_BYTES

#todo verify all fields
class Option:
    def __init__(self, code, content):
        """Creates an Option with the specified option code & content."""
      # assert (code in ALL_OPTIONS)
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
    def unpack( packed_bytes ):
        (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return Option( opt_code, content )

#wip continue here
class Comment(Option):
    SPEC_CODE = 1
    def __init__(self, content_str):    Option.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { Comment.SPEC_CODE : Comment.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        print( '210 opt_code={} content_len={}'.format(opt_code, content_len))
        assert opt_code == Comment.SPEC_CODE     #todo copy check to all
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        print( '211 content_pad={} content={}'.format(content_pad, content))
        return Comment(content)

#-----------------------------------------------------------------------------
class CustomOption(Option):
    def __init__(self, code, content):
        """Creates an SHB Option with the specified option code & content."""
        Option.__init__( self, code, content )

    def to_map(self):           return util.select_keys( self.__dict__, ['code', 'pen_val', 'content'] )
    def __repr__(self):         return str( self.to_map() )
    def __eq__(self, other):    return self.to_map() == other.to_map()
    def __ne__(self, other):    return (not __eq__(self,other))

class CustomStringCopyable(CustomOption):
    SPEC_CODE = 2988
    def __init__(self, pen_val, content):
        pen.assert_valid_pen(pen_val)
        self.code       = self.SPEC_CODE
        self.pen_val    = pen_val
        self.content    = to_bytes(content)

    def pack(self):
        content_len     = len(self.content)
        spec_len        = content_len + 4   # spec definition of length includes PEN
        print( '140 CSC.pack()    content={} content_len={} spec_len={} '.format( self.content, content_len, spec_len ))
        content_pad     = util.block32_pad_bytes(self.content)
        packed_bytes    = struct.pack( '=HHL', self.code, spec_len, self.pen_val ) + content_pad
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { CustomStringCopyable.SPEC_CODE : CustomStringCopyable.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, spec_len, pen_val) = struct.unpack('=HHL', packed_bytes[:8])
        content_len     = spec_len - 4
        content_pad     = packed_bytes[8:]
        content         = content_pad[:content_len]
        print( '140 CSC.unpack()  content={} content_len={} spec_len={} '.format( content, content_len, spec_len ))
        return CustomStringCopyable( pen_val, content )

class CustomBinaryCopyable(CustomOption):
    SPEC_CODE = 2989
    def __init__(self, pen_val, content):
        pen.assert_valid_pen(pen_val)
        self.code       = self.SPEC_CODE
        self.pen_val    = pen_val
        self.content    = to_bytes(content)

    def pack(self):
        content_len     = len(self.content)
        spec_len        = content_len + 4   # spec definition of length includes PEN
        content_pad     = util.block32_pad_bytes(self.content)
        packed_bytes    = struct.pack( '=HHL', self.code, spec_len, self.pen_val ) + content_pad
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { CustomBinaryCopyable.SPEC_CODE : CustomBinaryCopyable.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, spec_len, pen_val) = struct.unpack('=HHL', packed_bytes[:8])
        content_len     = spec_len - 4
        content_pad     = packed_bytes[8:]
        content         = content_pad[:content_len]
        return CustomBinaryCopyable( pen_val, content )

class CustomStringNonCopyable(CustomOption):
    SPEC_CODE = 19372
    def __init__(self, pen_val, content):
        pen.assert_valid_pen(pen_val)
        self.code       = self.SPEC_CODE
        self.pen_val    = pen_val
        self.content    = to_bytes(content)

    def pack(self):
        content_len     = len(self.content)
        spec_len        = content_len + 4   # spec definition of length includes PEN
        content_pad     = util.block32_pad_bytes(self.content)
        packed_bytes    = struct.pack( '=HHL', self.code, spec_len, self.pen_val ) + content_pad
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { CustomStringNonCopyable.SPEC_CODE : CustomStringNonCopyable.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, spec_len, pen_val) = struct.unpack('=HHL', packed_bytes[:8])
        content_len     = spec_len - 4
        content_pad     = packed_bytes[8:]
        content         = content_pad[:content_len]
        return CustomStringNonCopyable( pen_val, content )

class CustomBinaryNonCopyable(CustomOption):
    SPEC_CODE = 19373
    def __init__(self, pen_val, content):
        pen.assert_valid_pen(pen_val)
        self.code       = self.SPEC_CODE
        self.pen_val    = pen_val
        self.content    = to_bytes(content)

    def pack(self):
        content_len     = len(self.content)
        spec_len        = content_len + 4   # spec definition of length includes PEN
        content_pad     = util.block32_pad_bytes(self.content)
        packed_bytes    = struct.pack( '=HHL', self.code, spec_len, self.pen_val ) + content_pad
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { CustomBinaryNonCopyable.SPEC_CODE : CustomBinaryNonCopyable.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, spec_len, pen_val) = struct.unpack('=HHL', packed_bytes[:8])
        content_len     = spec_len - 4
        content_pad     = packed_bytes[8:]
        content         = content_pad[:content_len]
        return CustomBinaryNonCopyable( pen_val, content )

#-----------------------------------------------------------------------------
class ShbOption(Option):
    def __init__(self, code, content, code_verify_disable=False):
        """Creates an SHB Option with the specified option code & content."""
        Option.__init__( self, code, content )

class ShbHardware(ShbOption):
    SPEC_CODE = 2
    def __init__(self, content_str):
        ShbOption.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { ShbHardware.SPEC_CODE : ShbHardware.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return ShbHardware(content)

class ShbOs(ShbOption):
    SPEC_CODE = 3
    def __init__(self, content_str):
        ShbOption.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { ShbOs.SPEC_CODE : ShbOs.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return ShbOs(content)

class ShbUserAppl(ShbOption):
    SPEC_CODE = 4
    def __init__(self, content_str):
        ShbOption.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { ShbUserAppl.SPEC_CODE : ShbUserAppl.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return ShbUserAppl(content)

#-----------------------------------------------------------------------------
class IdbOption(Option):
    def __init__(self, code, content, code_verify_disable=False):
        """Creates an IDB Option with the specified option code & content."""
        Option.__init__( self, code, content )

class IdbName(IdbOption):
    SPEC_CODE = 2
    def __init__(self, content_str):
        IdbOption.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { IdbName.SPEC_CODE : IdbName.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return IdbName(content)

class IdbDescription(IdbOption):
    SPEC_CODE = 3
    def __init__(self, content_str):
        IdbOption.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { IdbDescription.SPEC_CODE : IdbDescription.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return IdbDescription(content)

class IdbIpv4Addr(IdbOption):
    SPEC_CODE = 4
    def __init__(self, addr_byte_lst, netmask_byte_lst):
        print( 'IdbIpv4Addr.__init__() - enter')
        addr_byte_lst       = list( addr_byte_lst )
        netmask_byte_lst    = list( netmask_byte_lst )
        util.assert_vec4_uint8( addr_byte_lst )
        util.assert_vec4_uint8( netmask_byte_lst )
        self.code           = self.SPEC_CODE
        self.addr_bytes     = addr_byte_lst
        self.netmask_bytes  = netmask_byte_lst
        print( 'IdbIpv4Addr.__init__() - exit')

    def to_map(self): return util.select_keys(self.__dict__, ['code', 'addr_bytes', 'netmask_bytes'])

    @staticmethod
    def dispatch_entry(): return { IdbIpv4Addr.SPEC_CODE : IdbIpv4Addr.unpack }

    def pack(self):   #todo needs test
        """Encodes into a bytes block."""
        packed_bytes = ( struct.pack('=HH', self.code, 8) + to_bytes(self.addr_bytes) + to_bytes(self.netmask_bytes))
        return packed_bytes

    @staticmethod
    def unpack( packed_bytes ):
        print( 'IdbIpv4Addr.unpack() - enter')
        assert len(packed_bytes) == 12      #todo check everywhere
        (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        assert opt_code == IdbIpv4Addr.SPEC_CODE    #todo check everywhere
        assert content_len == 8    #todo check everywhere
        addr_val    = util.bytes_to_uint8_list( packed_bytes[4:8]  )
        netmask_val = util.bytes_to_uint8_list( packed_bytes[8:12] )
        result = IdbIpv4Addr( addr_val, netmask_val )
        print( 'IdbIpv4Addr.unpack() - result=', result)
        print( 'IdbIpv4Addr.unpack() - exit')
        return result

class IdbIpv6Addr(IdbOption):
    SPEC_CODE = 5
    def __init__(self, addr_byte_lst, prefix_len):
        print( 'IdbIpv6Addr.__init__() - enter')
        print( 'addr_byte_lst={} prefix_len={}'.format( addr_byte_lst, prefix_len ))
        addr_byte_lst       = list( addr_byte_lst )
        util.assert_vec16_uint8( addr_byte_lst )
        assert 0 <= prefix_len  <= 128
        self.code           = self.SPEC_CODE
        self.addr_bytes     = addr_byte_lst
        self.prefix_len     = prefix_len
        print( 'IdbIpv6Addr.__init__() - exit')

    def to_map(self): return util.select_keys(self.__dict__, ['code', 'addr_bytes', 'prefix_len'])

    @staticmethod
    def dispatch_entry(): return { IdbIpv6Addr.SPEC_CODE : IdbIpv6Addr.unpack }

    def pack(self):   #todo needs test
        """Encodes into a bytes block."""
        content = to_bytes(self.addr_bytes) + to_bytes( [self.prefix_len] )
        content_len = len(content)
        assert content_len == 17
        content_pad = util.block32_pad_bytes( content )
        packed_bytes = struct.pack('=HH', self.code, content_len) + content_pad
        util.assert_block32_length( packed_bytes )  #todo add to all
        return packed_bytes

    @staticmethod
    def unpack( packed_bytes ):
        print( 'IdbIpv6Addr.unpack() - enter')      #todo remove dbg prints
        util.assert_block32_length( packed_bytes )  #todo add to all
        assert len(packed_bytes) == 24      #todo check everywhere
        (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        assert opt_code == IdbIpv6Addr.SPEC_CODE    #todo check everywhere
        assert content_len == 17    #todo check everywhere
        addr_val        = util.bytes_to_uint8_list( packed_bytes[4:20]  )
        (prefix_len,)   = util.bytes_to_uint8_list( packed_bytes[20:21] )
        result = IdbIpv6Addr( addr_val, prefix_len )
        print( 'IdbIpv6Addr.unpack() - result=', result)
        print( 'IdbIpv6Addr.unpack() - exit')
        return result

class IdbMacAddr(IdbOption):
    SPEC_CODE = 6
    def __init__(self, addr_byte_lst):
        print( 'IdbMacAddr.__init__() - enter')
        addr_byte_lst       = list( addr_byte_lst )
        assert len(addr_byte_lst) == 6
        util.assert_uint8_list( addr_byte_lst )
        self.code           = self.SPEC_CODE
        self.addr_bytes     = addr_byte_lst
        print( 'IdbMacAddr.__init__() - exit')

    def to_map(self): return util.select_keys(self.__dict__, ['code', 'addr_bytes'])

    @staticmethod
    def dispatch_entry(): return { IdbMacAddr.SPEC_CODE : IdbMacAddr.unpack }

    def pack(self):   #todo needs test
        """Encodes into a bytes block."""
        content = to_bytes(self.addr_bytes)
        content_len = len(content)
        assert content_len == 6
        content_pad = util.block32_pad_bytes( content )
        packed_bytes = struct.pack('=HH', self.code, content_len) + content_pad
        util.assert_block32_length( packed_bytes )  #todo add to all
        return packed_bytes

    @staticmethod
    def unpack( packed_bytes ):
        print( 'IdbMacAddr.unpack() - enter')      #todo remove dbg prints
        util.assert_block32_length( packed_bytes )  #todo add to all
        assert len(packed_bytes) == 12      #todo check everywhere
        (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        assert opt_code == IdbMacAddr.SPEC_CODE    #todo check everywhere
        assert content_len == 6    #todo check everywhere
        addr_val    = util.bytes_to_uint8_list( packed_bytes[4:10]  )
        result      = IdbMacAddr( addr_val )
        print( 'IdbMacAddr.unpack() - result=', result)
        print( 'IdbMacAddr.unpack() - exit')
        return result

class IdbEuiAddr(IdbOption):
    SPEC_CODE = 7
    # BLOCK_LEN = Block32Len( 12 )   #todo create class for this; then BLOCK_LEN.assert_equals( len_val )

    def __init__(self, addr_byte_lst):
        addr_byte_lst = list( addr_byte_lst )
        assert len(addr_byte_lst) == 8
        util.assert_uint8_list( addr_byte_lst )
        self.code           = self.SPEC_CODE
        self.addr_bytes     = addr_byte_lst

    def to_map(self): return util.select_keys(self.__dict__, ['code', 'addr_bytes'])

    def pack(self):
        """Encodes into a bytes block."""
        content = to_bytes(self.addr_bytes)
        content_len = len(content)
        assert content_len == 8
        packed_bytes = add_header( self.code, content_len, content )
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { IdbEuiAddr.SPEC_CODE : IdbEuiAddr.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        util.assert_block32_length( packed_bytes )  #todo add to all
        assert len(packed_bytes) == 12      #todo check everywhere
        (opt_code, content_len, content) = strip_header( packed_bytes )
        assert opt_code == IdbEuiAddr.SPEC_CODE    #todo check everywhere
        assert content_len == 8    #todo check everywhere
        addr_val    = util.bytes_to_uint8_list( content )
        result      = IdbEuiAddr( addr_val )
        return result

class IdbSpeed(IdbOption):
    SPEC_CODE = 8
    # BLOCK_LEN = Block32Len( 12 )   #todo create class for this; then BLOCK_LEN.assert_equals( len_val )

    def __init__(self, speed):
        util.assert_uint64(speed)
        self.code   = self.SPEC_CODE
        self.speed  = speed

    def to_map(self): return util.select_keys(self.__dict__, ['code', 'speed'])

    def pack(self):
        """Encodes into a bytes block."""
        content =  uint64_pack( self.speed )
        content_len = 8     #todo content_len unneeded?
        packed_bytes = add_header( self.code, content_len, content )
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { IdbSpeed.SPEC_CODE : IdbSpeed.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len, content) = strip_header( packed_bytes )
        assert opt_code == IdbSpeed.SPEC_CODE    #todo check everywhere
        assert content_len == 8    #todo check everywhere
        speed   = uint64_unpack( content )
        result  = IdbSpeed( speed )
        return result

class IdbTsResol(IdbOption):
    SPEC_CODE = 9
  # BLOCK_LEN = Block32Len( 12 )   #todo create class for this; then BLOCK_LEN.assert_equals( len_val )
    POWER_2_BITMASK     = 0x80
    POWER_10_BITMASK    = 0x00
    EXPONENT_BITMASK    = 0x7F

    def __init__(self, ts_resol_exponent, is_power_2=False):
        assert 0 <= ts_resol_exponent <= 127    # 7 bits only + decimal/binary flag bit
        self.code   = self.SPEC_CODE
        self.ts_resol_power  = ts_resol_exponent
        self.is_power_2  = is_power_2

    def get_ts_resolution_secs(self):
        if (self.is_power_2):
            return pow(  2, -self.ts_resol_power )
        else:
            return pow( 10, -self.ts_resol_power )

    def to_map(self): return util.select_keys(self.__dict__, ['code', 'ts_resol_power', 'is_power_2'])

    def pack(self):
        """Encodes into a bytes block."""
        if (self.is_power_2):
            bitmask = IdbTsResol.POWER_2_BITMASK
        else:
            bitmask = IdbTsResol.POWER_10_BITMASK
        byte_val = bitmask | self.ts_resol_power
        content =  uint8_pack( byte_val )
        content_len = 1     #todo content_len unneeded?
        packed_bytes = add_header( self.code, content_len, content )
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { IdbTsResol.SPEC_CODE : IdbTsResol.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len, content) = strip_header( packed_bytes )
        assert opt_code == IdbTsResol.SPEC_CODE    #todo check everywhere
        assert content_len == 1    #todo check everywhere
        byte_val   = uint8_unpack( content )
        is_power_2 = bool( byte_val & IdbTsResol.POWER_2_BITMASK )
        ts_resol_power = byte_val & IdbTsResol.EXPONENT_BITMASK
        result  = IdbTsResol( ts_resol_power, is_power_2 )
        return result

class IdbTZone(IdbOption):
    SPEC_CODE = 10
    # BLOCK_LEN = Block32Len( 12 )   #todo create class for this; then BLOCK_LEN.assert_equals( len_val )

    def __init__(self, offset):     #todo PCAPNG spec leaves interpretation of offset unspecified
        self.code   = self.SPEC_CODE
        self.offset = offset

    def to_map(self): return util.select_keys(self.__dict__, ['code', 'offset'])

    def pack(self):
        """Encodes into a bytes block."""
        content = float32_pack( self.offset )
        content_len = 4     #todo content_len unneeded?
        packed_bytes = add_header( self.code, content_len, content )
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { IdbTZone.SPEC_CODE : IdbTZone.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len, content) = strip_header( packed_bytes )
        assert opt_code == IdbTZone.SPEC_CODE    #todo check everywhere
        assert content_len == 4    #todo check everywhere
        offset = float32_unpack( content )
        result = IdbTZone( offset )
        return result

class IdbFilter(IdbOption):   #todo spec says "TODO: Appendix XXX"
    SPEC_CODE = 11
    def __init__(self, content_str):
        IdbOption.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { IdbFilter.SPEC_CODE : IdbFilter.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len, content) = strip_header( packed_bytes )
        assert opt_code == IdbFilter.SPEC_CODE    #todo check everywhere
        return IdbFilter(content)

class IdbOs(IdbOption):
    SPEC_CODE = 12
    def __init__(self, content_str):
        IdbOption.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { IdbOs.SPEC_CODE : IdbOs.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len, content) = strip_header( packed_bytes )
        assert opt_code == IdbOs.SPEC_CODE    #todo check everywhere
        return IdbOs(content)

class IdbFcsLen(IdbOption):
    SPEC_CODE = 13
    # BLOCK_LEN = Block32Len( 12 )   #todo create class for this; then BLOCK_LEN.assert_equals( len_val )

    def __init__(self, fcs_len):
        util.assert_uint8( fcs_len )
        self.code       = self.SPEC_CODE
        self.fcs_len    = fcs_len

    def to_map(self): return util.select_keys(self.__dict__, ['code', 'fcs_len'])

    def pack(self):
        """Encodes into a bytes block."""
        content =  uint8_pack( self.fcs_len )
        content_len = 1     #todo content_len unneeded?
        packed_bytes = add_header( self.code, content_len, content )
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { IdbFcsLen.SPEC_CODE : IdbFcsLen.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len, content) = strip_header( packed_bytes )
        assert opt_code == IdbFcsLen.SPEC_CODE    #todo check everywhere
        assert content_len == 1    #todo check everywhere
        fcs_len = uint8_unpack( content )
        result  = IdbFcsLen( fcs_len )
        return result

class IdbTsOffset(IdbOption):   #todo maybe make this uint64 type?
    SPEC_CODE = 14
    # BLOCK_LEN = Block32Len( 12 )   #todo create class for this; then BLOCK_LEN.assert_equals( len_val )

    def __init__(self, ts_offset):     #todo PCAPNG spec leaves interpretation of ts_offset unspecified
        self.code       = self.SPEC_CODE
        self.ts_offset  = ts_offset

    def to_map(self): return util.select_keys(self.__dict__, ['code', 'ts_offset'])

    def pack(self):
        """Encodes into a bytes block."""
        content = int64_pack( self.ts_offset )
        content_len = 8     #todo content_len unneeded?
        packed_bytes = add_header( self.code, content_len, content )
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { IdbTsOffset.SPEC_CODE : IdbTsOffset.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len, content) = strip_header( packed_bytes )
        assert opt_code == IdbTsOffset.SPEC_CODE    #todo check everywhere
        assert content_len == 8    #todo check everywhere
        ts_offset = int64_unpack( content )
        result = IdbTsOffset( ts_offset )
        return result

#-----------------------------------------------------------------------------
class EpbOption(Option):    #todo -> Abstract (or all base classes)
    def __init__(self, code, content):
        """Creates an EPB Option with the specified option code & content."""
        Option.__init__( self, code, content )

class EpbFlags(EpbOption):
    SPEC_CODE = 2
    def __init__(self, content):
        content = to_bytes(content)
        assert len(content) == 4
        EpbOption.__init__(self, self.SPEC_CODE, content)

    @staticmethod
    def dispatch_entry(): return { EpbFlags.SPEC_CODE : EpbFlags.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len, content) = strip_header( packed_bytes )
        assert opt_code == EpbFlags.SPEC_CODE    #todo check everywhere
        assert content_len == 4    #todo check everywhere
        result = EpbFlags( content )
        return result

class EpbHash(EpbOption):
    SPEC_CODE = 3
    def __init__(self, content_str):
        EpbOption.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { EpbHash.SPEC_CODE : EpbHash.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len, content) = strip_header( packed_bytes )
        assert opt_code == EpbHash.SPEC_CODE    #todo check everywhere
        result = EpbHash( content )
        return result

class EpbDropCount(EpbOption):
    SPEC_CODE = 4
    # BLOCK_LEN = Block32Len( 12 )   #todo create class for this; then BLOCK_LEN.assert_equals( len_val )

    def __init__(self, dropcount):     #todo PCAPNG spec leaves interpretation of dropcount unspecified
        self.code       = self.SPEC_CODE
        self.dropcount  = dropcount

    def to_map(self): return util.select_keys(self.__dict__, ['code', 'dropcount'])

    def pack(self):
        """Encodes into a bytes block."""
        content = uint64_pack( self.dropcount )
        content_len = 8     #todo content_len unneeded?
        packed_bytes = add_header( self.code, content_len, content )
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { EpbDropCount.SPEC_CODE : EpbDropCount.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        (opt_code, content_len, content) = strip_header( packed_bytes )
        assert opt_code == EpbDropCount.SPEC_CODE    #todo check everywhere
        assert content_len == 8    #todo check everywhere
        dropcount = uint64_unpack( content )
        result = EpbDropCount( dropcount )
        return result

#-----------------------------------------------------------------------------
#todo add options for all blocks/classes

#todo need way to pack generic options: integer, string, float, object

def pack_all(opts_lst):  #todo needs test
    #todo verify all fields
    """Encodes an options from a dictionary into a bytes block."""
    util.assert_type_list(opts_lst)
    cum_result = ''
    for opt in opts_lst:
        cum_result += opt.pack()
    cum_result += Option.END_OF_OPT_BYTES
    return cum_result

def segment_rolling(raw_bytes):     #todo inline below
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
    return ( opt_bytes, raw_bytes_remaining )

def segment_all(raw_bytes):
    """Decodes a block of raw bytes into a list of segments."""
    util.assert_type_bytes(raw_bytes)
    util.assert_block32_length(raw_bytes)
    segments = []
    while ( 0 < len(raw_bytes) ):
        ( segment, raw_bytes_remaining ) = segment_rolling(raw_bytes)
        segments.append( segment )
        raw_bytes = raw_bytes_remaining
    return segments


def unpack_dispatch( dispatch_tbl, packed_bytes ):
    (opt_code, content_len) = struct.unpack('=HH', packed_bytes[:4])    #todo endian
    dispatch_fn = dispatch_tbl[ opt_code ]
    if (dispatch_fn != None):
        result =  dispatch_fn( packed_bytes )
        return result
    else:
        print( 'warning - option.unpack_dispatch(): unrecognized Option={}'.format( opt_code )) #todo log
        raise Exception( 'unpack_dispatch(): unrecognized option opt_code={}'.format(opt_code))

def unpack_all(dispatch_table, options_bytes):
    result = []
    option_segs_lst = segment_all(options_bytes)
    for opt_bytes in option_segs_lst:
        if is_end_of_opt( opt_bytes ):
            continue
        else:
            new_opt = unpack_dispatch( dispatch_table, opt_bytes )
            result.append(new_opt)
    return result

