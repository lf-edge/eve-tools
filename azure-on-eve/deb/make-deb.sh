# create the deb package structure
mkdir -p lfedge-eve-tools/DEBIAN
mkdir -p lfedge-eve-tools/usr/libexec/aziot-identity-service
mkdir lfedge-eve-tools/usr/bin
mkdir lfedge-eve-tools/usr/lib
mkdir lfedge-eve-tools/usr/include

# copy the control files
cp -p control/postinst lfedge-eve-tools/DEBIAN
cp -p control/preinst lfedge-eve-tools/DEBIAN

# copy files
cp ../aziotd/aziotd lfedge-eve-tools/usr/libexec/aziot-identity-service
cp ../build/libiothsm.so.1.0.8 lfedge-eve-tools/usr/lib
cp ../../eve-tools/eve_run lfedge-eve-tools/usr/bin
cp ../../eve-tools/tools/read_ek_public lfedge-eve-tools/usr/bin
cp ../../eve-tools/lib/include/eve_tpm_service.h lfedge-eve-tools/usr/include
cp ../../eve-tools/libevetools.so lfedge-eve-tools/usr/lib

# create the control file
cat << EOF > lfedge-eve-tools/DEBIAN/control
Package: lfedge-eve-tools
Version: 3.3.0
Section: admin
Priority: extra
Architecture: all
Depends: libprotobuf-dev
Provides: libiothsm
Replaces: libiothsm-std
Essential: no
Maintainer: github.com/cshari-zededa/lfedge-eve-tools
Description: Library and Tools to interact with Edge Virtualization Engine(EVE)
EOF

# create the deb package
dpkg-deb --build lfedge-eve-tools

# cleanup
rm -rf lfedge-eve-tools