#!/bin/bash
# Auto-install PyObjC if not present

python3 -c "import objc" 2>/dev/null
if [ $? -ne 0 ]; then
    python3 -m pip install --user pyobjc-core pyobjc-framework-Cocoa 2>/dev/null || \
    pip3 install --user pyobjc-core pyobjc-framework-Cocoa 2>/dev/null
fi
