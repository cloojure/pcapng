"""
Constants & functions for defining PCAPNG options.

See:

http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#formatopt
"""

OPT_END_OF_OPT    =     0

OPT_COMMENT       =     1

#todo need to do validation on data values & lengths
# custom options
OPT_CUSTOM_0      =  2988
OPT_CUSTOM_1      =  2989
OPT_CUSTOM_2      = 19372
OPT_CUSTOM_3      = 19373

#todo need to do validation on data values & lengths
# section header block options
OPT_SHB_HARDWARE  = 2
OPT_SHB_OS        = 3
OPT_SHB_USERAPPL  = 4

#todo need to do validation on data values & lengths
# interface description block options
IF_NAME           =   2
IF_DESCRIPTION    =   3
IF_IPV4ADDR       =   4
IF_IPV6ADDR       =   5
IF_MACADDR        =   6
IF_EUIADDR        =   7
IF_SPEED          =   8
IF_TSRESOL        =   9
IF_TZONE          =  10
IF_FILTER         =  11
IF_OS             =  12
IF_FCSLEN         =  13
IF_TSOFFSET       =  14

def assert_custom_option(opt_code):
    valid_opts = { OPT_CUSTOM_0, OPT_CUSTOM_1, OPT_CUSTOM_2, OPT_CUSTOM_3 }
    assert (opt_code in valid_opts)

def assert_shb_option(opt_code):
    valid_opts = { OPT_SHB_HARDWARE, OPT_SHB_OS, OPT_SHB_USERAPPL }
    assert (opt_code in valid_opts)

def assert_if_option(opt_code):
    valid_opts = {  IF_NAME, IF_DESCRIPTION, IF_IPV4ADDR, IF_IPV6ADDR, IF_MACADDR, IF_EUIADDR,
                    IF_SPEED, IF_TSRESOL, IF_TZONE, IF_FILTER, IF_OS, IF_FCSLEN, IF_TSOFFSET }
    assert (opt_code in valid_opts)
