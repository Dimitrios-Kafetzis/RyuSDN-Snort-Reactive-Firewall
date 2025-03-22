# Ryu SDN Controller based Reactive Firewall with Snort IDS Integration
---
This repository contains a Ryu-based reactive firewall application that integrates with Snort IDS. It dynamically blacklists and blocks malicious traffic by installing drop flow rules on an OpenFlow switch when Snort alerts detect suspicious activity.
## Features
- **Dynamic Blacklisting**: Automatically adds IPv4 (source, destination) pairs to a blacklist upon receiving an alert from Snort IDS.
- **Reactive Flow Installation**: Installs high-priority drop rules in the OpenFlow switch to block further malicious traffic.
- **Traffic Mirroring**: Forwards packets to a designated Snort port for real-time intrusion detection.
- **Snort Integration**: Utilizes the Ryu snortlib to interface with Snort IDS, processing alerts and associated packet data.

## Prerequisites
- **Ryu SDN Framework**: Ryu documentation
- **OpenFlow Switch**: e.g., Open vSwitch (OvS) configured to work with the Ryu controller.
- **Snort IDS**: Properly configured to work with the application via a UNIX socket.
- **Python**: Ensure compatibility with your Ryu installation.
- **Dependencies**: The application relies on snortlib (for Snort communication) and a helper module ryufunc (for switch discovery and flow installation).

## Installation
### 1. Clone the Repository:
```bash
git clone https://github.com/Dimitrios-Kafetzis/RyuApplications.git
cd RyuApplications
```
### 2. Install Ryu and Other Dependencies:
```bash
pip install ryu
```
Ensure that the additional dependencies (snortlib and ryufunc) are installed and properly configured.
### 3. Configure Snort IDS:
Set up Snort IDS to communicate with the controller using a UNIX socket as specified in the code.

## Usage
### 1. Start the Ryu Controller:
Launch the application with the Ryu manager:
```bash
ryu-manager ryu_sdn_snort_reactive_blacklisting_firewall_v3_1_DK.py
```
### 2. Deploy/OpenFlow Switch:
Connect your OpenFlow switch (e.g., OvS) to the Ryu controller.
### 3. Monitor Operation:
The application listens for Snort alerts, prints alert messages and packet details, and installs flow rules to drop packets matching the detected malicious IP pairs.

## Code Overview
- **File**: ryu_sdn_snort_reactive_blacklisting_firewall_v3_1_DK.py
- **Snort Integration**: Uses snortlib to receive alerts and extract packet data.
- **Blacklisting**: Maintains a list of malicious IP address tuples.
- **Flow Rule Management**: Employs functions from the ryufunc module to:
  - Discover the switch (using its DPID).
  - Add drop flow rules with a 60-second idle and hard timeout.
- **Packet Handling*: Standard packet-in event processing to learn MAC addresses and mirror packets to the Snort port.

## License
This project is licensed under the Apache License, Version 2.0.

## Authors
- Dimitrios Kafetzis (dimitrioskafetzis@gmail.com)
- Nippon Telegraph and Telecom Corporation
