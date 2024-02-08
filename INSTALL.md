
# Build and Install EVE Guest Services Libraries and Tools

## On Linux

### Installing on Ubuntu

The dpkg files are available the respective release artifacts page. 

e.g. to install v2.0.0 version of lfedge-eve-tools on Ubuntu, follow these steps:

`wget https://github.com/lf-edge/eve-tools/releases/download/v3.0.0/cshari-zededa.list`

`sudo cp cshari-zededa.list /etc/apt/sources.list.d/`

`sudo apt update`

`sudo apt install lfedge-eve-tools`

### Building Ubuntu 20.04

#### 1. Install the prerequisite libraries:
```bash
apt-get update && apt-get install -y bash libprotobuf-dev \
libprotoc-dev protobuf-compiler libssl-dev libcurl4-openssl-dev \
uuid-dev g++ make cmake curl gcc g++ git jq pkg-config libclang1 llvm-dev
```

#### 2. [Install Azure IoT Edge Runtime](https://docs.microsoft.com/en-us/azure/iot-edge/how-to-install-iot-edge-linux)

#### 3. Build EVE TPM API library:
```bash
cd eve-tools
make
sudo make install
```
  
#### 4. Build the EVE specific HSM plugin for Azure IoT Edge 1.2:
 
```bash
cd azure-on-eve
git submodule update --init --recursive
mkdir build; cd build
cmake -Drun_unittests=OFF -DUSE_TEST_TPM_INTERFACE_IN_MEM=OFF -DBUILD_SHARED=ON -Duse_cppunittest=OFF ..
cmake --build .
sudo cp libiothsm.so* /usr/lib
```

Note: if you encountered errors while building the code using OpenSSL 3, you might need to add changes from this [PR](https://github.com/Azure/azure-c-shared-utility/pull/577).

#### 5. Build the EVE specific HSM plugin for Azure IoT Edge 1.4:
 
```bash
cd azure-on-eve/aziotd
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y
export PATH="$PATH:/root/.cargo/bin"
cargo install bindgen --version '^0.54'
cargo install cbindgen --version '^0.15'
git clone https://github.com/Azure/iot-identity-service.git
cp iot-identity-service.diff iot-identity-service/
cd iot-identity-service
git reset --hard 15f59c8bd33b1fd8581a74ae6e5ea145c8cb1b9b
git apply iot-identity-service.diff
FORCE_NO_UNITTEST=1 make
```


#### 5. After this restart IoT Edge Runtime, for the plugin to take effect:

`sudo /etc/init.d/iotedge restart`
