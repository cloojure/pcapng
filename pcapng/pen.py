"""
IANA Private Enterprise Numbers

See:

    https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
"""

# Brocade Private Enterprise Number (PEN)
#   see:  http://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
#   Brocade Communications Systems, Inc.
#     Scott Kipp
#     skipp@brocade.com
BROCADE_PEN = 1588 #todo  add other Brocade PEN values?
#todo switch to a dict approach to avoid duplication

#todo  add all PEN values?

VALID_PENS = { BROCADE_PEN }

#todo check type on all fns
def assert_valid_pen( pen ):
    assert pen in VALID_PENS

