#!/bin/bash
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

set -e

ROOT_DIR="$(pwd)"
SERVER_DIR="$ROOT_DIR/server"
CLIENT_DIR="$ROOT_DIR/client"
VCOM_DIR="$ROOT_DIR/vcomlink"
CERT_FILE="server_cert.pem"

echo "Building server..."
make -C "$SERVER_DIR" build

echo "Building client..."
make -C "$CLIENT_DIR" build

echo "Building vcomlink server..."
make -C "$VCOM_DIR" build

echo "Running server with --gen-certs..."
cd "$SERVER_DIR/bin"
./verifier --gen-certs
if [ $? -ne 0 ]; then
    echo "Failed to run server with --gen-certs"
    exit 1
fi
if [ ! -f "$CERT_FILE" ]; then
    echo "Certificate file '$CERT_FILE' not found in root."
    exit 1
fi
cd "$ROOT_DIR"

echo "Copying $CERT_FILE to client/bin/ ..."
cp "$SERVER_DIR/bin/$CERT_FILE" "$CLIENT_DIR/bin/"

echo "Done."
