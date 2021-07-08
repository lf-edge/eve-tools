
# Build and Install EVE Guest Services Libraries and Tools

## On Linux

### Installing on Ubuntu

The dpkg files are available the respective release artifacts page. 

e.g. to install v2.0.0 version of lfedge-eve-tools on Ubuntu, follow these steps:

`wget https://github.com/cshari-zededa/lfedge-eve-tools/releases/download/v2.0.0/cshari-zededa.list`

`sudo cp cshari-zededa.list /etc/apt/sources.list.d/`

`sudo apt update`

`sudo apt install lfedge-eve-tools`

### Building On Debian/Ubuntu

#### 1. Install the prerequisite libraries:
`sudo apt-get install -y docker.io libprotobuf-dev libprotoc-dev protobuf-compiler cmake g++ libssl-dev libcurl4-openssl-dev uuid-dev`

#### 2. [Install Azure IoT Edge Runtime](https://docs.microsoft.com/en-us/azure/iot-edge/how-to-install-iot-edge-linux)

#### 3. First build EVE TPM API library:
`cd eve-tools`

`make`

`sudo make install`
  
 #### 4. Then build the EVE specific HSM plugin for Azure IoT Edge:
 
`docker build --no-cache . -t <your image name>`
Copy the aziotd Elf present in root directory of resulting image to your aziot vm.


#### 5. After this restart IoT Edge Runtime, for the plugin to take effect:

`sudo /etc/init.d/iotedge restart`
