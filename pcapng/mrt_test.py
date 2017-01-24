import struct
import pcapng.linktype
import pcapng.core
import pcapng.option
import pcapng.mrt
import pcapng.util
from pcapng.util import to_bytes, str_to_bytes


def test_mrt_block():
    pcapng.util.test_time_utc_set(123.456789)
    blk_bytes = pcapng.mrt.mrt_block_pack(2, 3, range(1, 6))
    blk_dict  = pcapng.mrt.mrt_block_unpack(blk_bytes)
    pcapng.util.assert_type_bytes(  blk_bytes )
    pcapng.util.assert_type_dict( blk_dict )
    assert blk_dict[ 'time_secs'    ] == 123
    assert blk_dict[ 'mrt_type'     ] == 2
    assert blk_dict[ 'mrt_subtype'  ] == 3
    assert blk_dict[ 'content'      ] == to_bytes( [1, 2, 3, 4, 5] )
    pcapng.util.test_time_utc_unset()

def test_mrt_block_ext():
    pcapng.util.test_time_utc_set(123.456789)
    blk_bytes = pcapng.mrt.mrt_block_extended_pack(4, 5, range(1, 8))
    blk_dict  = pcapng.mrt.mrt_block_extended_unpack(blk_bytes)
    pcapng.util.assert_type_bytes(  blk_bytes )
    pcapng.util.assert_type_dict( blk_dict )
    assert blk_dict[ 'time_secs'    ] == 123
    assert blk_dict[ 'time_usecs'   ] == 456789
    assert blk_dict[ 'mrt_type'     ] == 4
    assert blk_dict[ 'mrt_subtype'  ] == 5
    assert blk_dict[ 'content'      ] == to_bytes( [1, 2, 3, 4, 5, 6, 7] )
    pcapng.util.test_time_utc_unset()

def test_isis_block():
    pcapng.util.test_time_utc_set(123.456789)
    blk_bytes = pcapng.mrt.mrt_isis_block_pack( range(1, 6))
    blk_dict  = pcapng.mrt.mrt_isis_block_unpack(blk_bytes)
    assert blk_dict[ 'time_secs'    ] == 123
    assert blk_dict[ 'mrt_type'     ] == pcapng.mrt.ISIS
    assert blk_dict[ 'mrt_subtype'  ] == 0
    assert blk_dict[ 'content'      ] == to_bytes( [1, 2, 3, 4, 5] )
    pcapng.util.test_time_utc_unset()

def test_isis_block_ext():
    pcapng.util.test_time_utc_set(123.456789)
    blk_bytes = pcapng.mrt.mrt_isis_block_extended_pack( range(1, 8))
    blk_dict  = pcapng.mrt.mrt_isis_block_extended_unpack(blk_bytes)
    assert blk_dict[ 'time_secs'    ] == 123
    assert blk_dict[ 'time_usecs'   ] == 456789
    assert blk_dict[ 'mrt_type'     ] == pcapng.mrt.ISIS_ET
    assert blk_dict[ 'mrt_subtype'  ] == 0
    assert blk_dict[ 'content'      ] == to_bytes( [1, 2, 3, 4, 5, 6, 7] )
    pcapng.util.test_time_utc_unset()


