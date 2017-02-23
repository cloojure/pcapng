# Copyright 2017 Brocade Communications Systems, Inc
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


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

