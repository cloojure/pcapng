import struct
import pcapng.linktype
import pcapng.core
import pcapng.option
import pcapng.mrt
import pcapng.util
from pcapng.util import to_bytes, str_to_bytes


def test_mrt_header():
    pcapng.util.set_test_time_utc( 123 )
    blk_bytes = pcapng.mrt.mrt_block_create( 2, 3, range(1,6))
    blk_dict  = pcapng.mrt.mrt_header_parse( blk_bytes )
    pcapng.util.assert_type_str(  blk_bytes )
    pcapng.util.assert_type_dict( blk_dict )

    assert blk_dict[ 'time_secs'    ] == 123
    assert blk_dict[ 'mrt_type'     ] == 2
    assert blk_dict[ 'mrt_subtype'  ] == 3
    assert blk_dict[ 'content'      ] == to_bytes( [1, 2, 3, 4, 5] )


