# UTMStack Windows Agent

![CI](https://github.com/UTMStack/windows-agent/workflows/CI/badge.svg)

## Installation and configuration in unattended mode

You can install UTMStack agent in unattended mode from the command line:
```
"UTMStack-Installer-X.X.X.exe" /verysilent /supressmsgboxes /host=IP_ADDRESS
```
Replace "X.X.X" in the installer name with your UTMStack version, and "IP_ADDRESS" with the adress of the probe host to which the agent should send collected data.
