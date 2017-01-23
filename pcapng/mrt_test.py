import struct
import pcapng.linktype
import pcapng.core
import pcapng.option
import pcapng.util
from pcapng.util import to_bytes, str_to_bytes


# def test_mrt_header():
#     blk_str     = pcapng.core.section_header_block_encode( opts )
#     blk_data    = pcapng.core.section_header_block_decode( blk_str )
#     pcapng.util.assert_type_str( blk_str )
#     pcapng.util.assert_type_dict( blk_data )
#     assert blk_data['block_type']           == 0x0A0D0D0A
#     assert blk_data['block_total_len']      == len( blk_str )
#     assert blk_data['block_total_len']      == blk_data['block_total_len_end']
#     assert blk_data['byte_order_magic']     == 0x1A2B3C4D
#     assert blk_data['major_version']        == 1
#     assert blk_data['minor_version']        == 0
#     assert blk_data['section_len']          == -1
#     assert blk_data['options_dict']         == opts

