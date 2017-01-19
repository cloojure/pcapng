#!/usr/bin/env python
import struct
import sys
import time
import math


def assert_python27():
    (major, minor, micro, release_level, serial) = sys.version_info
    assert major == 2
    assert minor == 7

assert_python27()


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

def assert_type_ByteList( lst ):    #todo UByteList ?
    assert_type_list( lst )
    for elem in lst:
        assert_uint8(elem)

#todo used anywhere?
def fmt_pcap_hdr( ts_sec, ts_usec, incl_len, orig_len ):
    packed = struct.pack( '>LLLL', ts_sec, ts_usec, incl_len, orig_len)
    return packed

def split_float( fval ):
    frac, whole = math.modf( fval )
    micros = int( round( frac * 1000000 ))
    return int(whole), micros

def curr_utc_time_tuple():
    utc_secs = time.time()
    secs, usecs = split_float( utc_secs )
    return secs, usecs

def timetup_to_float( secs, usecs ):
    return secs + (usecs / 1000000.0)

def timetup_subtract( ts1, ts2 ):
    (s1, us1) = ts1
    (s2, us2) = ts2
    t1 = timetup_to_float( s1, us1 )
    t2 = timetup_to_float( s2, us2 )
    delta = t2 - t1
    return delta

def str_to_ByteList(arg):
    #todo verify input type & values [0..255]
    bytearr = list( map( int, bytearray(arg) ))
    return bytearr

def ByteList_to_ChrList(arg):
    #todo verify input type & values [0..255]
    charArray = list( map( chr, arg ))
    return charArray

#todo rename char_list_to_str
def ChrList_to_str(arg):
    #todo verify input type & values [0..255]
    strval = ''.join( arg )
    return strval

def ByteList_to_str(arg):
    #todo verify input type & values [0..255]
    strval = ChrList_to_str(ByteList_to_ChrList(arg))
    return strval

def first( lst ):
    return lst[0]

def pad_to_len(data, tolen, padval=0):
    assert_type_list(data)
    elem_needed = tolen - len(data)
    assert (elem_needed >= 0), "padding cannot be negative"
    result = data + [padval]*elem_needed
    return result

def block32_pad_len(curr_len):
    curr_blks = float(curr_len) / 4.0
    pad_blks = int( math.ceil( curr_blks ))
    pad_len = pad_blks * 4
    return pad_len

def pad_to_block32(data):
    assert_type_list(data)
    pad_len = block32_pad_len( len(data) )
    result = pad_to_len(data, pad_len)
    return result

def assert_block32_size(data):
    assert_type_list(data)
    assert (0 == len(data) % 4), "data must be 32-bit aligned"
    return True

