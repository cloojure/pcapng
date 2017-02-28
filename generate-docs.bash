#!/bin/bash
mkdir -p doc
echo ""
echo "pdoc $(pdoc --version) running..."
pdoc --html ./pcapng --overwrite --html-dir ./doc
echo "  done.  View docs in browser (system dependent):"
echo ""
echo "      gopen ./doc/pcapng/index.html       # or use chrome, firefox, etc"
echo ""
