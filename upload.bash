#!/bin/bash -v


echo "clearing old build output"
rm -rf dist *.egg-info      

echo "init for source distribution"
python setup.py sdist

if [[ true ]]; then     # use 'true' or 'false' (no quotes)
  # for testing until you get it right
  echo "uploading data  *** USING TESTPYPI ***"
  twine upload dist/* -r testpypi
  echo "to install, perform:"
  echo ""
  echo '  sudo pip install -i https://testpypi.python.org/pypi   'pcapng==1.2.3'   # *** use new version number *** '
  echo ""
else
  # normal production path
  echo "uploading data to pypi.org"
  twine upload dist/*
  echo "to install, perform:"
  echo ""
  echo '  sudo pip install pcapng '
  echo ""
fi

