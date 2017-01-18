#!/bin/bash 

echo ""
echo ">>> clearing old build output"
rm -rf dist *.egg-info      

echo ""
echo ">>> init for source distribution"
echo ""
python setup.py sdist

# MANUAL STEP: python setup.py register  -r https://testpypi.python.org/pypi   # *** for TESTPYPI # ***
# MANUAL STEP: python setup.py register 

# true  => use testpypi (for practice)
# false => use     pypi (the real one)
if false; then     # use 'true' or 'false' (no quotes)
  # for testing until you get it right
  echo ""
  echo ">>> uploading data  *** USING TESTPYPI ***"
  echo ""
  twine upload dist/* -r testpypi

  echo ""
  echo ">>> to install, perform:"
  echo ""
  echo ">>>    sudo pip install -i https://testpypi.python.org/pypi   'pcapng==1.2.3'   # *** use new version number *** "
  echo ""
else
  # normal production path
  echo ""
  echo ">>> uploading data to pypi.org"
  echo ""
  twine upload dist/*
  echo ""
  echo ">>> to install, perform:"
  echo ""
  echo ">>>    sudo pip install 'pcapng==1.2.3'   # *** use new version number ***  "
  echo ""
fi

