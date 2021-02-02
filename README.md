# UTMStack Windows Agent
![CI](https://github.com/UTMStack/windows-agent/workflows/CI/badge.svg)
[![Quality Gate Status](https://qube.atlasinside.com/api/project_badges/measure?project=UTMStack_windows-agent&metric=alert_status)](https://qube.atlasinside.com/dashboard?id=UTMStack_windows-agent)
[![Bugs](https://qube.atlasinside.com/api/project_badges/measure?project=UTMStack_windows-agent&metric=bugs)](https://qube.atlasinside.com/dashboard?id=UTMStack_windows-agent)
[![Code Smells](https://qube.atlasinside.com/api/project_badges/measure?project=UTMStack_windows-agent&metric=code_smells)](https://qube.atlasinside.com/dashboard?id=UTMStack_windows-agent)
[![Duplicated Lines (%)](https://qube.atlasinside.com/api/project_badges/measure?project=UTMStack_windows-agent&metric=duplicated_lines_density)](https://qube.atlasinside.com/dashboard?id=UTMStack_windows-agent)
[![Lines of Code](https://qube.atlasinside.com/api/project_badges/measure?project=UTMStack_windows-agent&metric=ncloc)](https://qube.atlasinside.com/dashboard?id=UTMStack_windows-agent)
[![Maintainability Rating](https://qube.atlasinside.com/api/project_badges/measure?project=UTMStack_windows-agent&metric=sqale_rating)](https://qube.atlasinside.com/dashboard?id=UTMStack_windows-agent)
[![Reliability Rating](https://qube.atlasinside.com/api/project_badges/measure?project=UTMStack_windows-agent&metric=reliability_rating)](https://qube.atlasinside.com/dashboard?id=UTMStack_windows-agent)
[![Security Rating](https://qube.atlasinside.com/api/project_badges/measure?project=UTMStack_windows-agent&metric=security_rating)](https://qube.atlasinside.com/dashboard?id=UTMStack_windows-agent)
[![Technical Debt](https://qube.atlasinside.com/api/project_badges/measure?project=UTMStack_windows-agent&metric=sqale_index)](https://qube.atlasinside.com/dashboard?id=UTMStack_windows-agent)
[![Vulnerabilities](https://qube.atlasinside.com/api/project_badges/measure?project=UTMStack_windows-agent&metric=vulnerabilities)](https://qube.atlasinside.com/dashboard?id=UTMStack_windows-agent)

## Pre-installation requirements

*	Compatible with Windows Server version 2012 R2 or higher.
*	The Windows agent for correct operation must have Powershell version 5 or higher installed.
*	In the case of Active Directory servers, TCP / UDP ports 389, TCP 636, TCP 3268, and TCP 3269 must be accessible from the probe. A service account must also be created with permissions to read the Active Directory data.
*	Download the agent from https://github.com/UTMStack/windows-agent/releases/

## Graphic Installation

*	Run windows-agent-[version].exe and follow the installation wizard.
*	Access the configuration panel through a browser, using the desktop shortcut or accessing to http://127.0.0.1:23948 
*	Configure the IP of the probe to which the agent will connect in the "Settings" tab.

## Installation and configuration in unattended mode

* You can install UTMStack agent in unattended mode from the command line:
```
windows-agent-[version].exe /verysilent /supressmsgboxes /host=IP_ADDRESS
```
Replace "IP_ADDRESS" with the adress of the probe host to which the agent should send collected data.
