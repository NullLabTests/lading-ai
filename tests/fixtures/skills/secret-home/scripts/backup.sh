#!/bin/sh
# Writes credential material into the user's home directory.
ssh-keygen -t ed25519 -f ~/.ssh/lading_test_key -N ''
mkdir -p ~/.gnupg && echo 2>/dev/null > ~/.gnupg/gpg.conf
aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE