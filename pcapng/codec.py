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
Functions for serializing/deserializing values for PCAPNG.
"""
import struct
import pcapng.util  as util
from   pcapng.util  import to_bytes

#-----------------------------------------------------------------------------
util.assert_python2()    #todo make work for python 2.7 or 3.3 ?
#-----------------------------------------------------------------------------


#todo add strict string reading conformance?
    # Section 3.5 of https://pcapng.github.io/pcapng states: "Software that reads these
    # files MUST NOT assume that strings are zero-terminated, and MUST treat a
    # zero-value octet as a string terminator."   We just use th length field to read in
    # strings, and don't terminate early if there is a zero-value byte.

#-----------------------------------------------------------------------------
#todo add endian global statemachine/var for write (testing) and read (host dependent)

#todo add tests for all methods

def uint8_pack(    arg ):       return struct.pack(   '=B', arg )
def uint8_unpack(  arg ):       return struct.unpack( '=B', arg )[0]
def uint16_pack(   arg ):       return struct.pack(   '=H', arg )
def uint16_unpack( arg ):       return struct.unpack( '=H', arg )[0]
def uint32_pack(   arg ):       return struct.pack(   '=L', arg )
def uint32_unpack( arg ):       return struct.unpack( '=L', arg )[0]
def uint64_pack(   arg ):       return struct.pack(   '=Q', arg )
def uint64_unpack( arg ):       return struct.unpack( '=Q', arg )[0]

def  int8_pack(    arg ):       return struct.pack(   '=b', arg )
def  int8_unpack(  arg ):       return struct.unpack( '=b', arg )[0]
def  int16_pack(   arg ):       return struct.pack(   '=h', arg )
def  int16_unpack( arg ):       return struct.unpack( '=h', arg )[0]
def  int32_pack(   arg ):       return struct.pack(   '=l', arg )
def  int32_unpack( arg ):       return struct.unpack( '=l', arg )[0]
def  int64_pack(   arg ):       return struct.pack(   '=q', arg )
def  int64_unpack( arg ):       return struct.unpack( '=q', arg )[0]

def float32_pack(   arg ):      return struct.pack(   '=f', arg )
def float32_unpack( arg ):      return struct.unpack( '=f', arg )[0]
def float64_pack(   arg ):      return struct.pack(   '=d', arg )
def float64_unpack( arg ):      return struct.unpack( '=d', arg )[0]

