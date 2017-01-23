import struct
import pcapng.linktype
import pcapng.core
import pcapng.option
import pcapng.mrt
import pcapng.util
from pcapng.util import to_bytes, str_to_bytes


def test_mrt_block():
    pcapng.util.set_test_time_utc( 123.456789 )
    blk_dict  = pcapng.mrt.mrt_block_parse(
                pcapng.mrt.mrt_block_create( 2, 3, range(1,6) ))
    pcapng.util.assert_type_str(  blk_bytes )
    pcapng.util.assert_type_dict( blk_dict )

    assert blk_dict[ 'time_secs'    ] == 123
    assert blk_dict[ 'mrt_type'     ] == 2
    assert blk_dict[ 'mrt_subtype'  ] == 3
    assert blk_dict[ 'content'      ] == to_bytes( [1, 2, 3, 4, 5] )

def test_mrt_block_ext():
    pcapng.util.set_test_time_utc( 123.456789 )
    blk_dict  = pcapng.mrt.mrt_block_extended_parse(
                pcapng.mrt.mrt_block_extended_create( 4, 5, range(1,8) ))
    pcapng.util.assert_type_str(  blk_bytes )
    pcapng.util.assert_type_dict( blk_dict )

    assert blk_dict[ 'time_secs'    ] == 123
    assert blk_dict[ 'time_usecs'   ] == 456789
    assert blk_dict[ 'mrt_type'     ] == 4
    assert blk_dict[ 'mrt_subtype'  ] == 5
    assert blk_dict[ 'content'      ] == to_bytes( [1, 2, 3, 4, 5, 6, 7] )


