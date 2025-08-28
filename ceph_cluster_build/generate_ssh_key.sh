#!/bin/bash

# Directory for keys
KEY_DIR="$HOME/.ssh"
KEY_FILE="$KEY_DIR/id_rsa"

# Create .ssh folder if not exists
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"

rm -f "$KEY_FILE" "$KEY_FILE.pub"

# Generate SSH key automatically (RSA 4096, no passphrase, overwrite without prompt)
ssh-keygen -t rsa -b 4096 -f "$KEY_FILE" -N "" -q

echo "✅ SSH key generated:"
echo "Private key: $KEY_FILE"
echo "Public key:  ${KEY_FILE}.pub"

