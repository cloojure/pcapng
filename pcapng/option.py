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
OPT_IDB_NAME            =   2
OPT_IDB_DESCRIPTION     =   3
OPT_IDB_IPV4ADDR        =   4
OPT_IDB_IPV6ADDR        =   5
OPT_IDB_MACADDR         =   6
OPT_IDB_EUIADDR         =   7
OPT_IDB_SPEED           =   8
OPT_IDB_TSRESOL         =   9
OPT_IDB_TZONE           =  10
OPT_IDB_FILTER          =  11
OPT_IDB_OS              =  12
OPT_IDB_FCSLEN          =  13
OPT_IDB_TSOFFSET        =  14

#todo need to do validation on data values & lengths
# enhanced packet block options
OPT_EPB_FLAGS           =   2
OPT_EPB_HASH            =   3
OPT_EPB_DROPCOUNT       =   4

#todo maybe need func to verify valid any option codes?

#todo need to do validation on data values & lengths
def assert_custom_option(opt_code):
    "Returns true if option code is valid for a custom block"
    valid_opts = { OPT_CUSTOM_0, OPT_CUSTOM_1, OPT_CUSTOM_2, OPT_CUSTOM_3 }
    assert (opt_code in valid_opts)

#todo need to do validation on data values & lengths
def assert_shb_option(opt_code):
    "Returns true if option code is valid for a segment header block"
    valid_opts = { OPT_SHB_HARDWARE, OPT_SHB_OS, OPT_SHB_USERAPPL }
    assert (opt_code in valid_opts)

#todo need to do validation on data values & lengths
def assert_ifc_desc_option(opt_code):
    "Returns true if option code is valid for a interface description block"
    valid_opts = {OPT_IDB_NAME, OPT_IDB_DESCRIPTION, OPT_IDB_IPV4ADDR, OPT_IDB_IPV6ADDR, OPT_IDB_MACADDR, OPT_IDB_EUIADDR,
                  OPT_IDB_SPEED, OPT_IDB_TSRESOL, OPT_IDB_TZONE, OPT_IDB_FILTER, OPT_IDB_OS, OPT_IDB_FCSLEN, OPT_IDB_TSOFFSET}
    assert (opt_code in valid_opts)

#todo need to do validation on data values & lengths
def assert_epb_option(opt_code):
    "Returns true if option code is valid for a enhanced packet block"
    valid_opts = { OPT_EPB_FLAGS, OPT_EPB_HASH, OPT_EPB_DROPCOUNT }
    assert (opt_code in valid_opts)

