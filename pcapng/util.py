import struct
import sys
import time
import math
import pcapng.const

#todo check type on all fns
#todo verify have tests for all

#todo migrate fns to general libs

# Global var's
test_ctx = {
    'enable'    : False,
    'utc_secs'  : -1.2      # floating point unix time
}
def test_time_utc_set(utc_secs):
    global test_ctx
    test_ctx['enable']      = True
    test_ctx['utc_time']    = utc_secs
def test_time_utc_unset():
    global test_ctx
    test_ctx['enable']      = False

#-----------------------------------------------------------------------------

def is_python2():
    (major, minor, micro, release_level, serial) = sys.version_info
    return ((major == 2) and (minor == 7))

def is_python3():
    (major, minor, micro, release_level, serial) = sys.version_info
    return ((major == 3) and (minor >= 5))

def assert_python2():
    assert is_python2()

#-----------------------------------------------------------------------------
#todo need tests for all

def assert_type_bytearray( arg ):
    assert type( arg ) == bytearray

def assert_type_bytes( arg ):
    assert type( arg ) == bytes

def assert_type_str( arg ):
    assert type( arg ) == str

def assert_type_list( arg ):
    assert type( arg ) == list

def assert_type_dict( arg ):
    assert type( arg ) == dict

def assert_uint8(arg):        # unsigned byte
    assert (0 <= arg <= 255)

def assert_int8(arg):          # signed byte
    assert (-128 <= arg <= 127)

def assert_uint32(arg):        # unsigned byte
    assert (0 <= arg < pcapng.const.POW_2_32)

#-----------------------------------------------------------------------------

#todo make a pow2_range(), pow2_thru() fns (0 1 2 4 8 16 32 ...)
#todo make a sqr_range(), sqr_thru() fns (0 1 2 4 9 16 25 36 ...)

#todo make a pow2_nbr_range(), pow2_nbr_thru() fns (0 1 2 3 4 5  7 8 9  15 16 17  31 32 33 ...)
#todo make a sqr_nbr_range(), sqr_nbr_thru() fns (0 1 2 3 4 5   8 9 10  15 16 17  24 25 26  35 36 37 ...)

#todo convert to common generator fn
def fibonacci_list( n ):
    "Returns a list of the first n Fibonacci numbers"
    result = [0, 1]
    while len(result) < n:
        next_fibo = result[-1] + result[-2]
        result.append( next_fibo )
    return result[:n]   # in case ask for len smaller than seed list

def fibonacci_range(maxVal):   #todo need test
    "Returns a list of Fibonacci numbers less than or equal to maxVal"
    result = [0, 1]
    done = False
    while not done:
        next_fibo = result[-1] + result[-2]
        if next_fibo <= maxVal:
            result.append( next_fibo )
        else:
            done = True
    return result

def to_bytes( arg ):
    """Converts arg to a 'bytes' object."""
    return bytes( bytearray( arg ))    # if python2, 'bytes' is synonym for 'str'

def str_to_bytes( arg ):
    """Converts a string arg to a 'bytes' object."""
    assert_type_str( arg )
    """Convert an ASCII string to 'bytes'. Works on both Python2 and Python3."""
    return to_bytes( map(ord,arg))

def int32_to_hexstr(arg):
    """Converts a 32-bit unsigned integer value to a hex string ."""
    assert_uint32(arg)
    return ( '0x' + format( curr_utc_secs(), '08x' ))

def split_float( fval ):
    """Splits a float into integer and fractional parts."""
    frac, whole = math.modf( fval )
    micros = int( round( frac * 1000000 ))
    return int(whole), micros

def curr_utc_timetuple():
    """Returns the current UTC time as a (secs, usecs) tuple."""
    global test_ctx
    if test_ctx['enable']:
        utc_secs = test_ctx['utc_time']
    else:
        utc_secs = time.time()
    secs, usecs = split_float( utc_secs )
    return secs, usecs

def curr_utc_secs():
    """Returns the current UTC time in integer seconds."""
    secs, usecs = curr_utc_timetuple()
    return secs

def curr_utc_secs_hexstr():
    """Returns the current UTC time in integer seconds."""
    return int32_to_hexstr(curr_utc_secs())

def timeTuple_to_float(secs, usecs):
    """Converts a time tuple from (secs, usecs) to float."""
    return secs + (usecs / 1000000.0)

def timeTuple_subtract(ts1, ts2):
    """Subtracts two time tuples in (secs, usecs) format, returning a float result."""
    (s1, us1) = ts1
    (s2, us2) = ts2
    t1 = timeTuple_to_float(s1, us1)
    t2 = timeTuple_to_float(s2, us2)
    delta = t2 - t1
    return delta

def chrList_to_str(arg):
    """ Convert a list of characters to a string"""
    #todo verify input type & values [0..255]
    strval = ''.join( arg )
    return strval

#todo move to pcapng.list (or delete?); only(), second(), last(), butlast(), rest()
def first( lst ):
    """Returns the first item in a sequence."""
    return lst[0]

def select_keys( src_dict, keys_lst ):
    """Returns a new dict containing the specified keys (& values) from src_dict."""
    result = {}
    for key in keys_lst:
        result[ key ] = src_dict[ key ]
    return result

def class_str( obj ):
    "Returns the class name of an object as a string"
    return obj.__class__.__name__


#todo move to pcapng.bytes
#-----------------------------------------------------------------------------

def block32_ceil_num_bytes(curr_len):
    """Returns the number of bytes (n >= curr_len) at the next 32-bit boundary"""
    num_blks = float(curr_len) / 4.0
    num_blks_pad = int( math.ceil( num_blks ))
    num_bytes_pad = num_blks_pad * 4
    return num_bytes_pad

def pad_bytes(data_bytes, tgt_length, padval=0):
    """Add (n>=0) 'padval' bytes to extend data to tgt_length"""
    num_bytes_needed = tgt_length - len(data_bytes)
    assert (num_bytes_needed >= 0), "padding cannot be negative"
    data_bytes_pad = to_bytes(data_bytes) + to_bytes([padval]) * num_bytes_needed
    return data_bytes_pad

def block32_pad_bytes(data_bytes):
    """Pad data with (n>=0) 0x00 bytes to reach the next 32-bit boundary"""
    padded_len = block32_ceil_num_bytes(len(data_bytes))
    return pad_bytes(data_bytes, padded_len)

def assert_block32_length(data):
    """Assert that data length is at a 32-bit boundary"""
    rem_bytes = len(data) % 4
    assert (0 == rem_bytes), ("data must be 32-bit aligned; len={}  rem_bytes={}".format(
        len(data), rem_bytes ))

def block32_bytes_pack( content=[] ):
    content_len = len( content )
    content_bytes_pad = block32_pad_bytes( content )
    packed_bytes = struct.pack( '=L', content_len ) + content_bytes_pad
    return packed_bytes

def block32_bytes_unpack_rolling( packed_bytes ):
    (content_len,) = struct.unpack( '=L', packed_bytes[:4] )
    content_len_pad = block32_ceil_num_bytes(content_len)
    packed_bytes_nohdr = packed_bytes[4:]
    content_bytes = packed_bytes_nohdr[:content_len]
    remaining_bytes = packed_bytes_nohdr[content_len_pad:]
    return content_bytes, remaining_bytes

def block32_labelled_bytes_pack( label, content=[] ):
    content_bytes_pad = block32_pad_bytes( content )
    content_len = len( content )
    total_len   = 12 + len( content_bytes_pad )
    packed_bytes = struct.pack( '=LLL', label, total_len, content_len ) + content_bytes_pad
    return packed_bytes

def block32_labelled_bytes_unpack_rolling( packed_bytes ):
    (label, total_len, content_len) = struct.unpack( '=LLL', packed_bytes[:12] )
    content_bytes       = packed_bytes[12:12+content_len]
    remaining_bytes     = packed_bytes[total_len:]
    return label, content_bytes, remaining_bytes

