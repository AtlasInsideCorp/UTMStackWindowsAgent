# UTMStack Windows Agent
![CI](https://github.com/UTMStack/windows-agent/workflows/CI/badge.svg)
[![Quality Gate Status](https://atlasinside-qube.eastus.cloudapp.azure.com/api/project_badges/measure?project=utmstack_windows_agent&metric=alert_status)](https://atlasinside-qube.eastus.cloudapp.azure.com/dashboard?id=utmstack_windows_agent)
[![Bugs](https://atlasinside-qube.eastus.cloudapp.azure.com/api/project_badges/measure?project=utmstack_windows_agent&metric=bugs)](https://atlasinside-qube.eastus.cloudapp.azure.com/dashboard?id=utmstack_windows_agent)
[![Code Smells](https://atlasinside-qube.eastus.cloudapp.azure.com/api/project_badges/measure?project=utmstack_windows_agent&metric=code_smells)](https://atlasinside-qube.eastus.cloudapp.azure.com/dashboard?id=utmstack_windows_agent)
[![Coverage](https://atlasinside-qube.eastus.cloudapp.azure.com/api/project_badges/measure?project=utmstack_windows_agent&metric=coverage)](https://atlasinside-qube.eastus.cloudapp.azure.com/dashboard?id=utmstack_windows_agent)
[![Duplicated Lines (%)](https://atlasinside-qube.eastus.cloudapp.azure.com/api/project_badges/measure?project=utmstack_windows_agent&metric=duplicated_lines_density)](https://atlasinside-qube.eastus.cloudapp.azure.com/dashboard?id=utmstack_windows_agent)
[![Lines of Code](https://atlasinside-qube.eastus.cloudapp.azure.com/api/project_badges/measure?project=utmstack_windows_agent&metric=ncloc)](https://atlasinside-qube.eastus.cloudapp.azure.com/dashboard?id=utmstack_windows_agent)
[![Maintainability Rating](https://atlasinside-qube.eastus.cloudapp.azure.com/api/project_badges/measure?project=utmstack_windows_agent&metric=sqale_rating)](https://atlasinside-qube.eastus.cloudapp.azure.com/dashboard?id=utmstack_windows_agent)
[![Reliability Rating](https://atlasinside-qube.eastus.cloudapp.azure.com/api/project_badges/measure?project=utmstack_windows_agent&metric=reliability_rating)](https://atlasinside-qube.eastus.cloudapp.azure.com/dashboard?id=utmstack_windows_agent)
[![Security Rating](https://atlasinside-qube.eastus.cloudapp.azure.com/api/project_badges/measure?project=utmstack_windows_agent&metric=security_rating)](https://atlasinside-qube.eastus.cloudapp.azure.com/dashboard?id=utmstack_windows_agent)
[![Technical Debt](https://atlasinside-qube.eastus.cloudapp.azure.com/api/project_badges/measure?project=utmstack_windows_agent&metric=sqale_index)](https://atlasinside-qube.eastus.cloudapp.azure.com/dashboard?id=utmstack_windows_agent)
[![Vulnerabilities](https://atlasinside-qube.eastus.cloudapp.azure.com/api/project_badges/measure?project=utmstack_windows_agent&metric=vulnerabilities)](https://atlasinside-qube.eastus.cloudapp.azure.com/dashboard?id=utmstack_windows_agent)

## Pre-installation requirements

*	Compatible with Windows Server version 2012 R2 or higher.
*	The Windows agent for correct operation must have Powershell version 5 or higher installed.
*	In the case of Active Directory servers, TCP / UDP ports 389, TCP 636, TCP 3268, and TCP 3269 must be accessible from the probe. A service account must also be created with permissions to read the Active Directory data.
*	Download the agent from https://updates.utmstack.com/assets/windows-agent-latest.exe

## Graphic Installation

*	Run windows-agent-latest.exe and follow the installation wizard.
*	Access the configuration panel through a browser, using the desktop shortcut or accessing to http://127.0.0.1:23948 
*	Configure the IP of the probe to which the agent will connect in the "Settings" tab.

## Installation and configuration in unattended mode

* You can install UTMStack agent in unattended mode from the command line:
```
windows-agent-latest.exe /verysilent /supressmsgboxes /host=IP_ADDRESS
```
Replace "IP_ADDRESS" with the adress of the probe host to which the agent should send collected data.
