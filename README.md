# Library and Tools to interact with Edge Virtualization Engine(EVE)

This repository contains library and tools required to interact with the Edge Virtualization Engine(EVE), an operating system built for the Edge devices, a project under Linux Foundation Edge (www.lfedge.org)

In a quick summary, Edge Virtualization Engine provides a uniform virtualization layer on various Edge gateways, using which Edge workloads can be deployed as Containers or Virtual Machines, commonly called the Edge Containers. For more details about EVE, please visit https://github.com/lf-edge/eve.

Edge Containers run in virtualized environment. However, in some cases, it is useful for the applications running inside these Edge Containers to have a way to interact with the host operating system(i.e. EVE), to collaboratively implement certain functionality for better agility, security and accuracy. Some example use cases below:

* An application might want to pin its identity with an EK on the hardware TPM ASIC, to make
sure its identity is sealed to the hardware platform it is running on.

* An application might want to have a way to communicate with its host operating system to establish a
liveliness check, where it can be restarted by the EVE layer, when the Edge Container turns
unresponsive for whatever reason.

* An application might want to know about its underlying physical network ports going down, so that
it can take any corrective action in a timely manner, like rerouting via backup link, or propagating
the failure either upstream or downstream.

* An application might want to get a view of physical resources consumed by the Edge VM or Container,
as seen by the host operating system, for accurate reporting of KPIs to its analytics services.

As a starting point, this codebase implements TPM related services:
1) A library to provide interface for talking to TPM ASIC on the host operating system (eve-tpm-tools/lib)
2) A customized version of libiothsm.so, to use with Azure IoT Edge Runtime, to use for TPM based DPS provisioning (azure-on-eve)
3) "eve_run" shell command, which is used to issue a selective set of TPM commands on the host operating system (eve-tools/tools)

Please refer to INSTALL.md for installation instructions.
Please open issues for any bugs or improvements. And Pull requests are welcome!
