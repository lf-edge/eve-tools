### How to run Tests

#### 1- TPM Emulation

Linux comes with a [vTPM proxy module](https://elixir.bootlin.com/linux/v5.19.17/source/drivers/char/tpm/tpm_vtpm_proxy.c) that can be used to emulate TPM locally as a character device, to do this first install:
```bash
sudo apt-get install swtpm tpm2-tools automake autoconf gcc sed
```

Load vTPM :
```bash
sudo modprobe tpm_vtpm_proxy
```

Install and compile the [linux-vtpm-tests](https://github.com/stefanberger/linux-vtpm-tests), we need `vtpmctrl` from this :
```bash
git clone https://github.com/stefanberger/linux-vtpm-tests.git 
cd linux-vtpm-tests 
./bootstrap.sh
./configure
make
make -j 10 check
```

Finally emulate the TPM:
```bash
sudo ./linux-vtpm-tests/src/vtpmctrl --tpm2 --spawn /bin/swtpm chardev --tpm2 --fd %fd --tpmstate dir=/tmp --flags not-need-init --locality allow-set-locality
```

#### 2- Run the tests
Build the VTPM image from EVE:
```bash
cd pkg/vtpm
docker build --no-cache .
```
Run VTPM image :
```bash
docker run --device=/dev/tpm0 --device=/dev/tpmrm0 -p 127.0.0.1:8877:8877/tcp <image id>
```

[Patch](https://github.com/lf-edge/eve-tools/blob/d25496bcb098724b81f9cb1e1547b89dc83e8ead/eve-tools/lib/src/sendrecv.cpp#L71) eve-tools to connect to `127.0.0.1`, rebuild it and then run tests:
```bash
make test
```