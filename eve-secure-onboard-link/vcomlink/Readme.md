# ⚠️ vComLink Service Code (Static Copy from EVE)

**Warning: This directory contains a static copy of the `vComLink` service from the [EVE (Edge Virtualization Engine)](https://github.com/lf-edge/eve) project.**

This copy exists **solely to support the testability and standalone execution** of the secure onboarding reference implementation **outside of EVE**.

## Important Notes

- This is **not an actively maintained or synced** copy of the original EVE source.
- It is **not intended for any use outside of testing**.
- The purpose is to make the onboarding logic testable and runnable in isolated environments.
- If you need the latest updates or wish to contribute to `vComLink`, please refer to the official EVE repository.

## Source of Truth

The official and maintained version of this service can be found here:  
[https://github.com/lf-edge/eve](https://github.com/lf-edge/eve)

Always refer to the upstream project for bug fixes, improvements, and security updates.

### Enabling vsock for Local Testing

You can check if `vsock` is available and load the modules as follows:

```bash
# Check if vsock is supported in your kernel
cat /boot/config-$(uname -r) | grep CONFIG_VSOCKETS

# You should see something like:
# CONFIG_VSOCKETS=m
# CONFIG_VSOCKETS_DIAG=m
# CONFIG_VSOCKETS_LOOPBACK=m

# Load the required modules
sudo modprobe vsock
sudo modprobe vsock_loopback
```

## License

This project is part of the LF Edge EVE tools suite. See the main repository for license information.
