#!/bin/bash

CA_CERT_FILE="ca.cer"
CA_CERT_PEM_FILE="ca.pem"
EK_CERT_FILE="ek.cer"
EK_CERT_PEM_FILE="ek.pem"

if ! command -v openssl &> /dev/null; then
    echo "Error: OpenSSL is not installed." >&2
    exit 1
fi

if ! command -v tpm2_getekcertificate &> /dev/null; then
    echo "Error: tpm2-tools is not installed." >&2
    exit 1
fi

cleanup () {
    rm -f "$EK_CERT_FILE" "$CA_CERT_FILE" "$EK_CERT_PEM_FILE" "$CA_CERT_PEM_FILE" > /dev/null 2>&1
}


if tpm2_getekcertificate -o "$EK_CERT_FILE" &> /dev/null; then
    echo "EK certificate successfully retrieved to $EK_CERT_FILE."
else
    echo "Error: Failed to retrieve EK certificate." >&2
    exit 1
fi

# Extract CA Issuers URI
CA_ISSUERS_URI=$(openssl x509 -in "$EK_CERT_FILE" -noout -text -inform der 2>/dev/null | grep -A1 "CA Issuers" | grep "URI:" | sed 's/^.*URI://')
if [ -z "$CA_ISSUERS_URI" ]; then
    echo "Error: Could not extract 'CA Issuers - URI' from the certificate." >&2
    cleanup
    exit 1
fi

echo "CA Issuers URI: \"$CA_ISSUERS_URI\""
if wget -q -O "$CA_CERT_FILE" "$CA_ISSUERS_URI"; then
    echo "CA certificate successfully downloaded to $CA_CERT_FILE."
else
    echo "Error: Failed to download CA certificate from $CA_ISSUERS_URI." >&2
    cleanup
    exit 1
fi

# Convert them to PEM format for verification
if openssl x509 -inform der -in "$EK_CERT_FILE" -outform pem -out "$EK_CERT_PEM_FILE"; then
    echo "EK certificate successfully converted to PEM format."
else
    echo "Error: Failed to convert EK certificate to PEM format." >&2
    cleanup
    exit 1
fi

if openssl x509 -inform der -in "$CA_CERT_FILE" -outform pem -out "$CA_CERT_PEM_FILE"; then
    echo "CA certificate successfully converted to PEM format."
else
    echo "Error: Failed to convert CA certificate to PEM format." >&2
    cleanup
    exit 1
fi

if openssl verify -CAfile "$CA_CERT_PEM_FILE" "$EK_CERT_FILE"; then
    echo "EK certificate is valid and verified against the CA certificate."
else
    echo "Error: EK certificate verification failed." >&2
    cleanup
    exit 1
fi

cleanup
exit 0
