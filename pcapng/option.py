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

import pcapng.codec as codec
import pcapng.pen   as pen
import pcapng.util  as util
from   pcapng.util  import to_bytes

#-----------------------------------------------------------------------------
util.assert_python2()    #todo make work for python 2.7 or 3.3 ?
#-----------------------------------------------------------------------------

#todo add docstrings for all classes
#todo add docstrings for all constructurs
#todo add docstrings for all methods

#todo add strict string reading conformance?
    # Section 3.5 of https://pcapng.github.io/pcapng states: "Software that reads these
    # files MUST NOT assume that strings are zero-terminated, and MUST treat a
    # zero-value octet as a string terminator."   We just use th length field to read in
    # strings, and don't terminate early if there is a zero-value byte.

#-----------------------------------------------------------------------------
#todo make analous fns for blocks?
def strip_header( packed_bytes ): #todo use for all unpack()
    "Utility function to strip Option type_code & length from packed bytes, returning all three."
    util.assert_block32_length( packed_bytes )
    (type_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
    content_pad = packed_bytes[4:]
    assert content_len <= len(content_pad)
    content = content_pad[:content_len]
    return (type_code, content_len, content)

#todo use everywhere
def add_header(type_code, content_len, content):   #todo delete content var?
    "Utility function to prepend an Option's type_code and length field to packed bytes, with 32-bit padding."
    content_pad = util.block32_pad_bytes( content )
    packed_bytes = struct.pack('=HH', type_code, content_len) + content_pad
    return packed_bytes

#todo all options need to do validation on data values & lengths
#todo verify all fields
#todo check type on all fn args

#todo verify all fields
class Option:
    "Superclass for all PCAPNG options"
#   OPT_UNKNOWN       =  9999   # non-standard      #todo use this?

    def __init__(self, type_code, content):
        "Creates an Option block"
        #todo assert valid type_code?
        self.type_code  = type_code
        self.content    = to_bytes(content)

    def to_map(self):
        "Converts to a map representation"
        return util.select_keys(self.__dict__, ['type_code', 'content'])
    def __repr__(self):         return str( self.to_map() )
    def __eq__(self, other):    return self.to_map() == other.to_map()
    def __ne__(self, other):    return (not __eq__(self,other))

    def pack(self):   #todo needs test
        "Serialize into packed bytes"
        #todo validate type_code
        data_len_orig   = len(self.content)
        data_pad        = util.block32_pad_bytes(self.content)
        packed_bytes    = struct.pack('=HH', self.type_code, data_len_orig) + data_pad
        return packed_bytes

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return Option( type_code, content )

class EndOfOptions(Option):
    "Degenerate class used as a sentinal value for Option packed bytes"
    # from PCAPNG spec
    SPEC_CODE = 0
    PACKED_BYTES = struct.pack('=HH', SPEC_CODE, 0)
    @staticmethod
    def is_end_of_opt( opt_bytes ):
        "Indicates a block of packed bytes is the End-of-Options sentinal"
        return opt_bytes == EndOfOptions.PACKED_BYTES

#wip continue here
class Comment(Option):
    "Serialize & deserialze a PCAPNG Comment Option"
    SPEC_CODE = 1
    def __init__(self, content_str):
        "Create an instance"
        Option.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { Comment.SPEC_CODE : Comment.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        print( '210 type_code={} content_len={}'.format(type_code, content_len))
        assert type_code == Comment.SPEC_CODE     #todo copy check to all
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        print( '211 content_pad={} content={}'.format(content_pad, content))
        return Comment(content)

#-----------------------------------------------------------------------------
class CustomOption(Option):
    "Superclass for all PCAPNG Custom Options"
    def __init__(self, type_code, content):
        "Create an instance"
        Option.__init__(self, type_code, content)

    def to_map(self):
        "Converts to a map representation"
        return util.select_keys( self.__dict__, ['type_code', 'pen_val', 'content'] )
    def __repr__(self):         return str( self.to_map() )
    def __eq__(self, other):    return self.to_map() == other.to_map()
    def __ne__(self, other):    return (not __eq__(self,other))

class CustomStringCopyable(CustomOption):
    "Serialize & deserialze a PCAPNG Custom String Copyable Option"
    SPEC_CODE = 2988
    def __init__(self, pen_val, content):
        "Create a PCAPNG Custom String Copyable Option"
        pen.assert_valid_pen(pen_val)
        self.type_code       = self.SPEC_CODE
        self.pen_val    = pen_val
        self.content    = to_bytes(content)

    def pack(self):
        "Serialize into packed bytes"
        content_len     = len(self.content)
        spec_len        = content_len + 4   # spec definition of length includes PEN
        print( '140 CSC.pack()    content={} content_len={} spec_len={} '.format( self.content, content_len, spec_len ))
        content_pad     = util.block32_pad_bytes(self.content)
        packed_bytes    = struct.pack( '=HHL', self.type_code, spec_len, self.pen_val ) + content_pad
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { CustomStringCopyable.SPEC_CODE : CustomStringCopyable.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, spec_len, pen_val) = struct.unpack('=HHL', packed_bytes[:8])
        content_len     = spec_len - 4
        content_pad     = packed_bytes[8:]
        content         = content_pad[:content_len]
        print( '140 CSC.unpack()  content={} content_len={} spec_len={} '.format( content, content_len, spec_len ))
        return CustomStringCopyable( pen_val, content )

class CustomBinaryCopyable(CustomOption):
    "Serialize & deserialze a PCAPNG Custom Binary Copyable Option"
    SPEC_CODE = 2989
    def __init__(self, pen_val, content):
        "Create an instance"
        pen.assert_valid_pen(pen_val)
        self.type_code       = self.SPEC_CODE
        self.pen_val    = pen_val
        self.content    = to_bytes(content)

    def pack(self):
        "Serialize into packed bytes"
        content_len     = len(self.content)
        spec_len        = content_len + 4   # spec definition of length includes PEN
        content_pad     = util.block32_pad_bytes(self.content)
        packed_bytes    = struct.pack( '=HHL', self.type_code, spec_len, self.pen_val ) + content_pad
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { CustomBinaryCopyable.SPEC_CODE : CustomBinaryCopyable.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, spec_len, pen_val) = struct.unpack('=HHL', packed_bytes[:8])
        content_len     = spec_len - 4
        content_pad     = packed_bytes[8:]
        content         = content_pad[:content_len]
        return CustomBinaryCopyable( pen_val, content )

class CustomStringNonCopyable(CustomOption):
    "Serialize & deserialze a PCAPNG Custom String Non-Copyable Option"
    SPEC_CODE = 19372
    def __init__(self, pen_val, content):
        "Create an instance"
        pen.assert_valid_pen(pen_val)
        self.type_code       = self.SPEC_CODE
        self.pen_val    = pen_val
        self.content    = to_bytes(content)

    def pack(self):
        "Serialize into packed bytes"
        content_len     = len(self.content)
        spec_len        = content_len + 4   # spec definition of length includes PEN
        content_pad     = util.block32_pad_bytes(self.content)
        packed_bytes    = struct.pack( '=HHL', self.type_code, spec_len, self.pen_val ) + content_pad
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { CustomStringNonCopyable.SPEC_CODE : CustomStringNonCopyable.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, spec_len, pen_val) = struct.unpack('=HHL', packed_bytes[:8])
        content_len     = spec_len - 4
        content_pad     = packed_bytes[8:]
        content         = content_pad[:content_len]
        return CustomStringNonCopyable( pen_val, content )

class CustomBinaryNonCopyable(CustomOption):
    "Serialize & deserialze a PCAPNG Custom Binary Non-Copyable Option"
    SPEC_CODE = 19373
    def __init__(self, pen_val, content):
        "Create an instance"
        pen.assert_valid_pen(pen_val)
        self.type_code       = self.SPEC_CODE
        self.pen_val    = pen_val
        self.content    = to_bytes(content)

    def pack(self):
        "Serialize into packed bytes"
        content_len     = len(self.content)
        spec_len        = content_len + 4   # spec definition of length includes PEN
        content_pad     = util.block32_pad_bytes(self.content)
        packed_bytes    = struct.pack( '=HHL', self.type_code, spec_len, self.pen_val ) + content_pad
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { CustomBinaryNonCopyable.SPEC_CODE : CustomBinaryNonCopyable.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, spec_len, pen_val) = struct.unpack('=HHL', packed_bytes[:8])
        content_len     = spec_len - 4
        content_pad     = packed_bytes[8:]
        content         = content_pad[:content_len]
        return CustomBinaryNonCopyable( pen_val, content )

#-----------------------------------------------------------------------------
class ShbOption(Option):
    "Superclass for all PCAPNG Segment Header Block Options"
    def __init__(self, type_code, content, code_verify_disable=False):
        "Create an instance"
        Option.__init__(self, type_code, content)

class ShbHardware(ShbOption):
    "Serialize & deserialze a PCAPNG SHB Hardware Option"
    SPEC_CODE = 2
    def __init__(self, content_str):
        "Create an instance"
        ShbOption.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { ShbHardware.SPEC_CODE : ShbHardware.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return ShbHardware(content)

class ShbOs(ShbOption):
    "Serialize & deserialze a PCAPNG SHB OS Option"
    SPEC_CODE = 3
    def __init__(self, content_str):
        "Create an instance"
        ShbOption.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { ShbOs.SPEC_CODE : ShbOs.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return ShbOs(content)

class ShbUserAppl(ShbOption):
    "Serialize & deserialze a PCAPNG SHB User Application Option"
    SPEC_CODE = 4
    def __init__(self, content_str):
        "Create an instance"
        ShbOption.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { ShbUserAppl.SPEC_CODE : ShbUserAppl.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return ShbUserAppl(content)

#-----------------------------------------------------------------------------
class IdbOption(Option):
    "Superclass for all PCAPNG Interface Description Block Options"
    def __init__(self, type_code, content, code_verify_disable=False):
        "Create an instance"
        Option.__init__(self, type_code, content)

class IdbName(IdbOption):
    "Serialize & deserialze a PCAPNG IDB Name Option"
    SPEC_CODE = 2
    def __init__(self, content_str):
        "Create an instance"
        IdbOption.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { IdbName.SPEC_CODE : IdbName.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return IdbName(content)

class IdbDescription(IdbOption):
    "Serialize & deserialze a PCAPNG IDB Description Option"
    SPEC_CODE = 3
    def __init__(self, content_str):
        "Create an instance"
        IdbOption.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { IdbDescription.SPEC_CODE : IdbDescription.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        content_pad = packed_bytes[4:]
        content = content_pad[:content_len]
        return IdbDescription(content)

class IdbIpv4Addr(IdbOption):
    "Serialize & deserialze a PCAPNG IPv4 Address Option"
    SPEC_CODE = 4
    def __init__(self, addr_byte_lst, netmask_byte_lst):
        "Create an instance"
        print( 'IdbIpv4Addr.__init__() - enter')
        addr_byte_lst       = list( addr_byte_lst )
        netmask_byte_lst    = list( netmask_byte_lst )
        util.assert_vec4_uint8( addr_byte_lst )
        util.assert_vec4_uint8( netmask_byte_lst )
        self.type_code           = self.SPEC_CODE
        self.addr_bytes     = addr_byte_lst
        self.netmask_bytes  = netmask_byte_lst
        print( 'IdbIpv4Addr.__init__() - exit')

    def to_map(self):
        "Converts to a map representation"
        return util.select_keys(self.__dict__, ['type_code', 'addr_bytes', 'netmask_bytes'])

    @staticmethod
    def dispatch_entry(): return { IdbIpv4Addr.SPEC_CODE : IdbIpv4Addr.unpack }

    def pack(self):   #todo needs test
        "Serialize to packed bytes"
        packed_bytes = ( struct.pack('=HH', self.type_code, 8) + to_bytes(self.addr_bytes) + to_bytes(self.netmask_bytes))
        return packed_bytes

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        print( 'IdbIpv4Addr.unpack() - enter')
        assert len(packed_bytes) == 12      #todo check everywhere
        (type_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        assert type_code == IdbIpv4Addr.SPEC_CODE    #todo check everywhere
        assert content_len == 8    #todo check everywhere
        addr_val    = util.bytes_to_uint8_list( packed_bytes[4:8]  )
        netmask_val = util.bytes_to_uint8_list( packed_bytes[8:12] )
        result = IdbIpv4Addr( addr_val, netmask_val )
        print( 'IdbIpv4Addr.unpack() - result=', result)
        print( 'IdbIpv4Addr.unpack() - exit')
        return result

class IdbIpv6Addr(IdbOption):
    "Serialize & deserialze a PCAPNG IPv6 Address Option"
    SPEC_CODE = 5
    def __init__(self, addr_byte_lst, prefix_len):
        "Create an instance"
        addr_byte_lst       = list( addr_byte_lst )
        util.assert_vec16_uint8( addr_byte_lst )
        assert 0 <= prefix_len  <= 128
        self.type_code           = self.SPEC_CODE
        self.addr_bytes     = addr_byte_lst
        self.prefix_len     = prefix_len

    def to_map(self):
        "Converts to a map representation"
        return util.select_keys(self.__dict__, ['type_code', 'addr_bytes', 'prefix_len'])

    @staticmethod
    def dispatch_entry(): return { IdbIpv6Addr.SPEC_CODE : IdbIpv6Addr.unpack }

    def pack(self):   #todo needs test
        "Serialize to packed bytes"
        content = to_bytes(self.addr_bytes) + to_bytes( [self.prefix_len] )
        content_len = len(content)
        assert content_len == 17
        content_pad = util.block32_pad_bytes( content )
        packed_bytes = struct.pack('=HH', self.type_code, content_len) + content_pad
        util.assert_block32_length( packed_bytes )  #todo add to all
        return packed_bytes

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        util.assert_block32_length( packed_bytes )  #todo add to all
        assert len(packed_bytes) == 24      #todo check everywhere
        (type_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        assert type_code == IdbIpv6Addr.SPEC_CODE    #todo check everywhere
        assert content_len == 17    #todo check everywhere
        addr_val        = util.bytes_to_uint8_list( packed_bytes[4:20]  )
        (prefix_len,)   = util.bytes_to_uint8_list( packed_bytes[20:21] )
        result = IdbIpv6Addr( addr_val, prefix_len )
        return result

class IdbMacAddr(IdbOption):
    "Serialize & deserialze a PCAPNG MAC Address Option"
    SPEC_CODE = 6
    def __init__(self, addr_byte_lst):
        "Create an instance"
        addr_byte_lst       = list( addr_byte_lst )
        assert len(addr_byte_lst) == 6
        util.assert_uint8_list( addr_byte_lst )
        self.type_code           = self.SPEC_CODE
        self.addr_bytes     = addr_byte_lst

    def to_map(self):
        "Converts to a map representation"
        return util.select_keys(self.__dict__, ['type_code', 'addr_bytes'])

    @staticmethod
    def dispatch_entry(): return { IdbMacAddr.SPEC_CODE : IdbMacAddr.unpack }

    def pack(self):   #todo needs test
        "Serialize to packed bytes"
        content = to_bytes(self.addr_bytes)
        content_len = len(content)
        assert content_len == 6
        content_pad = util.block32_pad_bytes( content )
        packed_bytes = struct.pack('=HH', self.type_code, content_len) + content_pad
        util.assert_block32_length( packed_bytes )  #todo add to all
        return packed_bytes

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        util.assert_block32_length( packed_bytes )  #todo add to all
        assert len(packed_bytes) == 12      #todo check everywhere
        (type_code, content_len) = struct.unpack('=HH', packed_bytes[:4])
        assert type_code == IdbMacAddr.SPEC_CODE    #todo check everywhere
        assert content_len == 6    #todo check everywhere
        addr_val    = util.bytes_to_uint8_list( packed_bytes[4:10]  )
        result      = IdbMacAddr( addr_val )
        return result

class IdbEuiAddr(IdbOption):
    "Serialize & deserialze a PCAPNG EUI Address Option"
    SPEC_CODE = 7
    # BLOCK_LEN = Block32Len( 12 )   #todo create class for this; then BLOCK_LEN.assert_equals( len_val )

    def __init__(self, addr_byte_lst):
        "Create an instance"
        addr_byte_lst = list( addr_byte_lst )
        assert len(addr_byte_lst) == 8
        util.assert_uint8_list( addr_byte_lst )
        self.type_code           = self.SPEC_CODE
        self.addr_bytes     = addr_byte_lst

    def to_map(self):
        "Converts to a map representation"
        return util.select_keys(self.__dict__, ['type_code', 'addr_bytes'])

    def pack(self):
        "Serialize to packed bytes"
        content = to_bytes(self.addr_bytes)
        content_len = len(content)
        assert content_len == 8
        packed_bytes = add_header( self.type_code, content_len, content )
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { IdbEuiAddr.SPEC_CODE : IdbEuiAddr.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        util.assert_block32_length( packed_bytes )  #todo add to all
        assert len(packed_bytes) == 12      #todo check everywhere
        (type_code, content_len, content) = strip_header( packed_bytes )
        assert type_code == IdbEuiAddr.SPEC_CODE    #todo check everywhere
        assert content_len == 8    #todo check everywhere
        addr_val    = util.bytes_to_uint8_list( content )
        result      = IdbEuiAddr( addr_val )
        return result

class IdbSpeed(IdbOption):
    "Serialize & deserialze a PCAPNG IDB Speed Option"
    SPEC_CODE = 8
    # BLOCK_LEN = Block32Len( 12 )   #todo create class for this; then BLOCK_LEN.assert_equals( len_val )

    def __init__(self, speed):
        "Create an instance"
        util.assert_uint64(speed)
        self.type_code   = self.SPEC_CODE
        self.speed  = speed

    def to_map(self):
        "Converts to a map representation"
        return util.select_keys(self.__dict__, ['type_code', 'speed'])

    def pack(self):
        "Serialize to packed bytes"
        content =  codec.uint64_pack( self.speed )
        content_len = 8     #todo content_len unneeded?
        packed_bytes = add_header( self.type_code, content_len, content )
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { IdbSpeed.SPEC_CODE : IdbSpeed.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, content_len, content) = strip_header( packed_bytes )
        assert type_code == IdbSpeed.SPEC_CODE    #todo check everywhere
        assert content_len == 8    #todo check everywhere
        speed   = codec.uint64_unpack( content )
        result  = IdbSpeed( speed )
        return result

class IdbTsResol(IdbOption):
    "Serialize & deserialze a PCAPNG IDB Timestamp Resolution Option"
    SPEC_CODE = 9
  # BLOCK_LEN = Block32Len( 12 )   #todo create class for this; then BLOCK_LEN.assert_equals( len_val )
    POWER_2_BITMASK     = 0x80
    POWER_10_BITMASK    = 0x00
    EXPONENT_BITMASK    = 0x7F

    def __init__(self, ts_resol_exponent, is_power_2=False):
        "Create an instance"
        assert 0 <= ts_resol_exponent <= 127    # 7 bits only + decimal/binary flag bit
        self.type_code   = self.SPEC_CODE
        self.ts_resol_power  = ts_resol_exponent
        self.is_power_2  = is_power_2

    def get_ts_resolution_secs(self):
        if (self.is_power_2):
            return pow(  2, -self.ts_resol_power )
        else:
            return pow( 10, -self.ts_resol_power )

    def to_map(self):
        "Converts to a map representation"
        return util.select_keys(self.__dict__, ['type_code', 'ts_resol_power', 'is_power_2'])

    def pack(self):
        "Serialize to packed bytes"
        if (self.is_power_2):
            bitmask = IdbTsResol.POWER_2_BITMASK
        else:
            bitmask = IdbTsResol.POWER_10_BITMASK
        byte_val = bitmask | self.ts_resol_power
        content =  codec.uint8_pack( byte_val )
        content_len = 1     #todo content_len unneeded?
        packed_bytes = add_header( self.type_code, content_len, content )
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { IdbTsResol.SPEC_CODE : IdbTsResol.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, content_len, content) = strip_header( packed_bytes )
        assert type_code == IdbTsResol.SPEC_CODE    #todo check everywhere
        assert content_len == 1    #todo check everywhere
        byte_val   = codec.uint8_unpack( content )
        is_power_2 = bool( byte_val & IdbTsResol.POWER_2_BITMASK )
        ts_resol_power = byte_val & IdbTsResol.EXPONENT_BITMASK
        result  = IdbTsResol( ts_resol_power, is_power_2 )
        return result

class IdbTZone(IdbOption):
    "Serialize & deserialze a PCAPNG IDB TimeZone Option"
    SPEC_CODE = 10
    # BLOCK_LEN = Block32Len( 12 )   #todo create class for this; then BLOCK_LEN.assert_equals( len_val )

    def __init__(self, offset):     #todo PCAPNG spec leaves interpretation of offset unspecified
        "Create an instance"
        self.type_code   = self.SPEC_CODE
        self.offset = offset

    def to_map(self):
        "Converts to a map representation"
        return util.select_keys(self.__dict__, ['type_code', 'offset'])

    def pack(self):
        "Serialize to packed bytes"
        content = codec.float32_pack( self.offset )
        content_len = 4     #todo content_len unneeded?
        packed_bytes = add_header( self.type_code, content_len, content )
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { IdbTZone.SPEC_CODE : IdbTZone.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, content_len, content) = strip_header( packed_bytes )
        assert type_code == IdbTZone.SPEC_CODE    #todo check everywhere
        assert content_len == 4    #todo check everywhere
        offset = codec.float32_unpack( content )
        result = IdbTZone( offset )
        return result

class IdbFilter(IdbOption):   #todo spec says "TODO: Appendix XXX"
    "Serialize & deserialze a PCAPNG IDB Filter Resolution Option"
    SPEC_CODE = 11
    def __init__(self, content_str):
        "Create an instance"
        IdbOption.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { IdbFilter.SPEC_CODE : IdbFilter.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, content_len, content) = strip_header( packed_bytes )
        assert type_code == IdbFilter.SPEC_CODE    #todo check everywhere
        return IdbFilter(content)

class IdbOs(IdbOption):
    "Serialize & deserialze a PCAPNG IDB OS Option"
    SPEC_CODE = 12
    def __init__(self, content_str):
        "Create an instance"
        IdbOption.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { IdbOs.SPEC_CODE : IdbOs.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, content_len, content) = strip_header( packed_bytes )
        assert type_code == IdbOs.SPEC_CODE    #todo check everywhere
        return IdbOs(content)

class IdbFcsLen(IdbOption):
    "Serialize & deserialze a PCAPNG IDB Frame Check Sequence (FCS) Length Option"
    SPEC_CODE = 13
    # BLOCK_LEN = Block32Len( 12 )   #todo create class for this; then BLOCK_LEN.assert_equals( len_val )

    def __init__(self, fcs_len):
        "Create an instance"
        util.assert_uint8( fcs_len )
        self.type_code       = self.SPEC_CODE
        self.fcs_len    = fcs_len

    def to_map(self):
        "Converts to a map representation"
        return util.select_keys(self.__dict__, ['type_code', 'fcs_len'])

    def pack(self):
        "Serialize to packed bytes"
        content =  codec.uint8_pack( self.fcs_len )
        content_len = 1     #todo content_len unneeded?
        packed_bytes = add_header( self.type_code, content_len, content )
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { IdbFcsLen.SPEC_CODE : IdbFcsLen.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, content_len, content) = strip_header( packed_bytes )
        assert type_code == IdbFcsLen.SPEC_CODE    #todo check everywhere
        assert content_len == 1    #todo check everywhere
        fcs_len = codec.uint8_unpack( content )
        result  = IdbFcsLen( fcs_len )
        return result

class IdbTsOffset(IdbOption):   #todo maybe make this uint64 type?
    "Serialize & deserialze a PCAPNG IDB Timestamp Offset Option"
    SPEC_CODE = 14
    # BLOCK_LEN = Block32Len( 12 )   #todo create class for this; then BLOCK_LEN.assert_equals( len_val )

    def __init__(self, ts_offset):     #todo PCAPNG spec leaves interpretation of ts_offset unspecified
        "Create an instance"
        self.type_code       = self.SPEC_CODE
        self.ts_offset  = ts_offset

    def to_map(self):
        "Converts to a map representation"
        return util.select_keys(self.__dict__, ['type_code', 'ts_offset'])

    def pack(self):
        "Serialize to packed bytes"
        content = codec.int64_pack( self.ts_offset )
        content_len = 8     #todo content_len unneeded?
        packed_bytes = add_header( self.type_code, content_len, content )
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { IdbTsOffset.SPEC_CODE : IdbTsOffset.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, content_len, content) = strip_header( packed_bytes )
        assert type_code == IdbTsOffset.SPEC_CODE    #todo check everywhere
        assert content_len == 8    #todo check everywhere
        ts_offset = codec.int64_unpack( content )
        result = IdbTsOffset( ts_offset )
        return result

#-----------------------------------------------------------------------------
class EpbOption(Option):    #todo -> Abstract (or all base classes)
    "Superclass for PCAPNG Enhanced Packet Block Options"
    def __init__(self, type_code, content):
        "Create an instance"
        Option.__init__(self, type_code, content)

class EpbFlags(EpbOption):
    "Serialize & deserialze a PCAPNG EPB Flags Option"
    SPEC_CODE = 2
    def __init__(self, content):
        "Create an instance"
        content = to_bytes(content)
        assert len(content) == 4
        EpbOption.__init__(self, self.SPEC_CODE, content)

    @staticmethod
    def dispatch_entry(): return { EpbFlags.SPEC_CODE : EpbFlags.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, content_len, content) = strip_header( packed_bytes )
        assert type_code == EpbFlags.SPEC_CODE    #todo check everywhere
        assert content_len == 4    #todo check everywhere
        result = EpbFlags( content )
        return result

class EpbHash(EpbOption):
    "Serialize & deserialze a PCAPNG EPB Hash Option"
    SPEC_CODE = 3
    def __init__(self, content_str):
        "Create an instance"
        EpbOption.__init__(self, self.SPEC_CODE, content_str)

    @staticmethod
    def dispatch_entry(): return { EpbHash.SPEC_CODE : EpbHash.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, content_len, content) = strip_header( packed_bytes )
        assert type_code == EpbHash.SPEC_CODE    #todo check everywhere
        result = EpbHash( content )
        return result

class EpbDropCount(EpbOption):
    "Serialize & deserialze a PCAPNG EPB Drop Count Option"
    SPEC_CODE = 4
    # BLOCK_LEN = Block32Len( 12 )   #todo create class for this; then BLOCK_LEN.assert_equals( len_val )

    def __init__(self, dropcount):     #todo PCAPNG spec leaves interpretation of dropcount unspecified
        "Create an instance"
        self.type_code       = self.SPEC_CODE
        self.dropcount  = dropcount

    def to_map(self):
        "Converts to a map representation"
        return util.select_keys(self.__dict__, ['type_code', 'dropcount'])

    def pack(self):
        "Serialize to packed bytes"
        content = codec.uint64_pack( self.dropcount )
        content_len = 8     #todo content_len unneeded?
        packed_bytes = add_header( self.type_code, content_len, content )
        return packed_bytes

    @staticmethod
    def dispatch_entry(): return { EpbDropCount.SPEC_CODE : EpbDropCount.unpack }

    @staticmethod
    def unpack( packed_bytes ):
        "Deserialize from packed bytes"
        (type_code, content_len, content) = strip_header( packed_bytes )
        assert type_code == EpbDropCount.SPEC_CODE    #todo check everywhere
        assert content_len == 8    #todo check everywhere
        dropcount = codec.uint64_unpack( content )
        result = EpbDropCount( dropcount )
        return result

#-----------------------------------------------------------------------------
#todo add options for all blocks/classes

#todo need way to pack generic options: integer, string, float, object

def pack_all(opts_lst):  #todo needs test
    #todo verify all fields
    """Given a list of options, converts each into packed bytes and concatenates the result"""
    util.assert_type_list(opts_lst)
    cum_result = ''
    for opt in opts_lst:
        cum_result += opt.pack()
    cum_result += EndOfOptions.PACKED_BYTES
    return cum_result

def segment_rolling(raw_bytes):     #todo inline below
    #todo verify all fields
    """Given the packed bytes for multiple options, unpacks and returns the first option object
    and the remaining packed bytes."""
    util.assert_type_bytes(raw_bytes)
    assert 4 <= len(raw_bytes)
    (type_code, content_len_orig) = struct.unpack( '=HH', raw_bytes[:4])
    content_len_pad = util.block32_ceil_num_bytes(content_len_orig)
    first_block_len_pad = 4 + content_len_pad
    assert first_block_len_pad <= len(raw_bytes)
    opt_bytes             = raw_bytes[ :first_block_len_pad   ]
    raw_bytes_remaining   = raw_bytes[  first_block_len_pad:  ]
    return ( opt_bytes, raw_bytes_remaining )

def segment_all(raw_bytes):
    """Given the packed bytes for multiple options,
    returns a list of packed bytes for the individual options."""
    util.assert_type_bytes(raw_bytes)
    util.assert_block32_length(raw_bytes)
    segments = []
    while ( 0 < len(raw_bytes) ):
        ( segment, raw_bytes_remaining ) = segment_rolling(raw_bytes)
        segments.append( segment )
        raw_bytes = raw_bytes_remaining
    return segments


def unpack_dispatch( dispatch_tbl, packed_bytes ):
    """Given a dispatch table associating Option type_code's to parsing functions, will invoke
    the appropriate unpacking function."""
    (type_code, content_len) = struct.unpack('=HH', packed_bytes[:4])    #todo endian
    dispatch_fn = dispatch_tbl[ type_code ]
    if (dispatch_fn is not None):
        result =  dispatch_fn( packed_bytes )
        return result
    else:
        #todo make generic OPT_UNKNOWN ?
        print( 'warning - option.unpack_dispatch(): unrecognized Option={}'.format( type_code )) #todo log
        raise Exception( 'unpack_dispatch(): unrecognized option type_code={}'.format(type_code))

def unpack_all(dispatch_table, options_bytes):
    """Given a dispatch table and the packed bytes for multiple options,
    unpacks the bytes and returns a list of Option objects."""
    result = []
    option_segs_lst = segment_all(options_bytes)
    for opt_bytes in option_segs_lst:
        if EndOfOptions.is_end_of_opt( opt_bytes ):
            continue
        else:
            new_opt = unpack_dispatch( dispatch_table, opt_bytes )
            result.append(new_opt)
    return result

