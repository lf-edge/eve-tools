# To use this patch, follow the steps below. 

On ubuntu 18.04, 

Uncomment the following lines in `/etc/apt/sources.list`:
`deb-src http://archive.ubuntu.com/ubuntu bionic main restricted`
`deb-src http://archive.ubuntu.com/ubuntu bionic-updates main restricted`

Add the following packages:
`sudo apt-get build-dep linux linux-image-$(uname -r)`
`sudo apt-get install libncurses-dev flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf git fakeroot`
 
Checkout kernel source code:
`git clone git://kernel.ubuntu.com/ubuntu/ubuntu-bionic.git` 

Apply the given patch:
`cd ubuntu-bionic`
`patch -p1 < 0001-Use-EVEEVEEVE-instead-of-KVMKVMKVM-to-check-for-KVM.patch`

Compile modified kernel source:
`LANG=C fakeroot debian/rules clean`
`LANG=C fakeroot debian/rules binary`

Install the new kernel binaries (binaries are typically available in the directory one level above ubuntu-bionic):
e.g. if the new binary tag is 4.15.0-48
`sudo dpkg -i linux*4.15.0-48*.deb`
`sudo reboot`

While booting, you have to choose the new kernel from Grub menu options, otherwise it will boot the old kernel.
To make the newly compiled kernel as the default one, please follow the steps below:
1. Find the menuentry tag, and submenu tag for the new kernel. e.g
   if Linux 4.15.0-48-generic is under submenu with tag `gnulinux-advanced-a7613e02-0f60-45be-b990-ef5f9c26db1e` and at menuentry tag `gnulinux-4.15.0-48-generic-advanced-a7613e02-0f60-45be-b990-ef5f9c26db1e`, then concatenate these 2 strings with a ">", e.g. "gnulinux-advanced-a7613e02-0f60-45be-b990-ef5f9c26db1e>gnulinux-4.15.0-48-generic-advanced-a7613e02-0f60-45be-b990-ef5f9c26db1e"
2. Set this string as GRUB_DEFAULT value in `/etc/default/grub`. e.g.
   GRUB_DEFAULT="gnulinux-advanced-a7613e02-0f60-45be-b990-ef5f9c26db1e>gnulinux-4.15.0-48-generic-advanced-a7613e02-0f60-45be-b990-ef5f9c26db1e"
3. `sudo update-grub2`
4. `sudo reboot`
