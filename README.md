# ptpsniffer
podman  run -it --rm --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW --privileged quay.io/aneeshkp/ptp-snipper:latest

🔍 Running NIC PTP Sniffer...
🔍 Checking PTP Announce message activity per NIC...

Interface: ovn-k8s-mp0     | PTP Announce Message: 0
Interface: br-ex           | PTP Announce Message: 0
Interface: eno1            | PTP Announce Message: 0
Interface: 60c4d0acaf46bbb | PTP Announce Message: 0
Interface: ens1f0          | PTP Announce Message: 238
Interface: 849e21e9218e516 | PTP Announce Message: 0
Interface: 5cc1b66f39d6092 | PTP Announce Message: 0
Interface: ens1f2          | PTP Announce Message: 198
Interface: ens2f1          | PTP Announce Message: 193

