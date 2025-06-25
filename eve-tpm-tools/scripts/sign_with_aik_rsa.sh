#!/bin/sh

# This example shows use case of signing a message in TPM, and
# verifying with openssl.
# AIK is generated from Primary Endorsement key, assumed to be at 0x81010001
# Data to be signed is arranged in "data_to_be_signed" file

AIK_HANDLE=0x81000003

echo "Using well-known AIK handle $AIK_HANDLE (RSA cipher and RSASSA signing scheme, with SHA256)"

echo "Preparing data_to_be_signed"
echo "secret data" > data_to_be_signed

echo "Preparing ticket file to pass for signing"
eve_run tpm2_hash -Q -C e -t ticket.bin  -g sha256 -o digest.bin data_to_be_signed

echo "Performing signing..."
eve_run tpm2_sign -Q -c $AIK_HANDLE -g sha256 -s rsassa -o data.out.sign -t ticket.bin -f plain data_to_be_signed

echo "Reading public key for using it in openssl"
eve_run tpm2_readpublic -Q -c $AIK_HANDLE -o ak.pub -f pem

echo "Verifying signature using openssl"
openssl dgst -verify ak.pub -keyform pem  -sha256 -signature data.out.sign data_to_be_signed

echo "Cleaning up"
rm -f ak.pub data_to_be_signed ticket.bin data.out.sign digest.bin
