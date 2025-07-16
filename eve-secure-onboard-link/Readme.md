# Secure Onboard Link (Reference Implementation)

This repository provides a reference implementation of the secure device onboarding workflow described in the document: **"Securely onboard device to a 3rd-party cloud Device Management Platforms"**.

The implementation demonstrates a TPM-backed provisioning sequence designed to establish cryptographic trust, validate device identity, and ensure secure communication with third-party cloud device management platforms (e.g., AWS IoT, Google Cloud IoT Core).


## Overview

This implementation follows a Zero Trust–aligned onboarding flow with:

- **TPM-based device identity verification and attestation**
- **Credential activation and signing key certification**
- **Certificate-based mutual authentication**
- **Full trust chain establishment**

The system consists of two main components:
- **Client**: Device-side application that performs TPM operations and communicates with the verifier
- **Verifier Server**: Cloud-side service that validates device identity and issues certificates

## Architecture

### Components

1. **Client Application**
   - Manages TPM operations (EK, AK, signing keys)
   - Handles device registration and activation
   - Performs certificate requests and secure communications

2. **Verifier Server**
   - Validates EK certificates and device identity
   - Performs TPM credential activation challenges
   - Issues signed certificates for authenticated devices
   - Provides secure endpoints for client communication

## Quick Start

### Prerequisites

- Go 1.19 or later
- TPM 2.0 hardware or simulator (for client)
- Make
- Docker (optional, for Alpine builds)

### Building the Project

Use the provided setup script to build both components:

```bash
./setup.sh
```

This script:
- Builds the verifier server, client application and vcomlink server
- Generates server certificates
- Copies certificates to appropriate locations

### Manual Build

Build components individually:

```bash
# Build verifier server
cd server
make build

# Build client
cd ../client
make build

# Build vcomlink-server for testing
cd ../vcomlink
make build
```

For static Alpine builds use `make alpine-build`.

## Usage

### Running the Verifier Server

1. **Generate server certificates** (if not using the setup script, one time only):
   ```bash
   cd server/bin
   ./verifier --gen-certs
   ```

2. **Start the verifier server**:
   ```bash
   # probably need skip-ek-verification flag for testing
   ./verifier --skip-ek-verification
   ```
   
   The server will listen on port 9191 by default.

3. **Start the vcomlink server**:
   ```bash
   ./vcomlink-server
   ```

### Running the Client

1. **Ensure server certificate is available** (if not using the setup script, one time only):
   ```bash
   # Copy server certificate to client directory
   cp server/bin/server_cert.pem client/bin/
   ```

2. **Run the client**:
   ```bash
   cd client/bin
   ./client
   ```
   
   Or specify a custom server URL:
   ```bash
   ./client --server https://your-server:9191
   ```

### Example Output

When running successfully, the client will display progress through each onboarding step:

```
[0] Initiating device registration and activation...
[1] Establishing trust in Attestation Key (AK)...
        Received device ID: 7ad98e564f68ecaac5a07260e92c5b1b597f1515ace4182c0547d95f425030c7
        Received token: eyJhbGciOiJIUzI1...
[2] Proving TPM holds the EK and AK can decrypt credential...
        Recovered credential: e3d478ef22cb182afb9b78d26187f5c2082a6d07122e41a0b29dc568938aa908
[3] Activation completed successfully, verifier now trusts the AK.
[4] Proving signing key is certified by the AK...
[5] Key certification completed successfully, verifier now trusts the signing key.
[6] Submitting CSR for certificate...
[7] CSR submitted successfully, received signed client certificate.
[8] Accessing secure endpoint with client certificate...
        Received data from server: "Super secret data"
[9] Secure endpoint accessed successfully, client certificate is valid.
[10] All operations completed successfully.
```

And server displays the corresponding messages:
```
[!] Skipping EK verification for untrusted devices
Loading CA certificate and key files...
2025/07/22 17:01:29 Server starting on port :9191...
[+] Received device init...
        TPM EK cert subject: 
        TPM EK cert issuer: CN=Nuvoton TPM Root CA 2112,O=Nuvoton Technology Corporation,C=TW
        TPM EK URL: [https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton TPM Root CA 2112.cer]
        Downloading issuing CA cert from URL: https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton TPM Root CA 2112.cer
        EK cert verified against issuing CA cert successfully
        EK verification failed EK public key does not match EK cert public key, but skipping due to configuration
        Untrusted device registered with ID: 7ad98e564f68ecaac5a07260e92c5b1b597f1515ace4182c0547d95f425030c7
[+] Received activate credential parameters from untrusted device...
        AK name matches AK public key
        AK meets the required attributes and is a restricted signing key
        Credential generated : e3d478ef22cb182afb9b78d26187f5c2082a6d07122e41a0b29dc568938aa908
        JWT generated for device : eyJhbGciOiJIUzI1NiIsInR5cCI6IkpX...
        Updated device registered with ID: 7ad98e564f68ecaac5a07260e92c5b1b597f1515ace4182c0547d95f425030c7
[+] Received activate credential request...
        Device ID from JWT : 7ad98e564f68ecaac5a07260e92c5b1b597f1515ace4182c0547d95f425030c7
        Device credential : e3d478ef22cb182afb9b78d26187f5c2082a6d07122e41a0b29dc568938aa908
        Recovered credential: e3d478ef22cb182afb9b78d26187f5c2082a6d07122e41a0b29dc568938aa908
        Recovered credential matches the device credential
        Device AK is now trusted
[+] Received key certification request from device 7ad98e564f68ecaac5a07260e92c5b1b597f1515ace4182c0547d95f425030c7
        Key certification payload signature verified successfully
        Attestation name matches object public key
        Key certification successful for device: 7ad98e564f68ecaac5a07260e92c5b1b597f1515ace4182c0547d95f425030c7
[+] Received request for CSR from device 7ad98e564f68ecaac5a07260e92c5b1b597f1515ace4182c0547d95f425030c7
        CSR signed with one of the device certified keys
        CSR signed successfully, sending back the certificate...
[+] Received access to the secure endpoint...
        Client certificate subject (device id): 7ad98e564f68ecaac5a07260e92c5b1b597f1515ace4182c0547d95f425030c7
        Client authorization successful
```

### API Endpoints

The verifier server exposes the following endpoints:

- `POST /device-init` - Initialize device registration
- `POST /activate-credential` - TPM credential activation challenge
- `POST /activate-credential-complete` - Complete credential activation
- `POST /prove-key-certification` - Verify key certification
- `POST /submit-csr` - Submit certificate signing request
- `POST /secure` - Secure endpoint requiring client certificate based auth

## ⚠️ Limitations

- This is a reference implementation for demonstration purposes
- Production deployments should implement additional security measures
- EK certificate validation may require integration with manufacturer CA chains

## License

This project is part of the LF Edge EVE tools suite. See the main repository for license information.

