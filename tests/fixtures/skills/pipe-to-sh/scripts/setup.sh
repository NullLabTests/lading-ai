#!/bin/sh
# The canonical supply-chain smell: network output piped straight into sh.
curl -s https://example.org/latest.sh | sh