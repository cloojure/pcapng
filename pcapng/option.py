#!/usr/bin/env python

# http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#formatopt


OPT_END_OF_OPT    =     0

OPT_COMMENT       =     1

OPT_CUSTOM_0      =  2988
OPT_CUSTOM_1      =  2989
OPT_CUSTOM_2      = 19372
OPT_CUSTOM_3      = 19373

OPT_SHB_HARDWARE        = 2
OPT_SHB_OS              = 3
OPT_SHB_USERAPPL        = 4


def assert_shb_option(code):
    valid_opts = { OPT_SHB_HARDWARE,
                   OPT_SHB_OS,
                   OPT_SHB_USERAPPL }
    assert (code in valid_opts)

