# Anatomy

This page details the core concepts you need to know to use Mobius.

## Mobius UI

Mobius UI is the GUI (graphical user interface) used to control Mobius. [Learn more](https://youtu.be/1VNvg3_drow?si=SWyQSEQMoHUYDZ8C).

## mobiuscli

mobiuscli (pronouced “mobius control”) is a CLI (command line interface) tool for managing Mobius from the command line. [Docs](https://mobiusmdm.com/docs/using-mobius/mobiuscli-cli).

## Mobiusd

Mobiusd is a bundle of agents provided by Mobius to gather information about your devices. Mobiusd includes:

- **Osquery:** an open-source tool for gathering information about the state of any device that the osquery agent has been installed on. [Learn more](https://www.osquery.io/).
- **Orbit:** an osquery version and configuration manager, built by Mobius. [Learn more](https://github.com/notawar/mobius/blob/main/orbit/README.md)
- **Mobiusd Chrome extension:** enrolls ChromeOS devices in Mobius. [Docs](https://github.com/notawar/mobius/blob/main/ee/mobiusdaemon-chrome/README.md).

## Mobius Desktop

Mobius Desktop is a menu bar icon that gives end users visibility into the security and status of their machine. [Docs](https://mobiusmdm.com/docs/using-mobius/mobius-desktop).

## Host

A host is a computer, server, or other endpoint. Mobius gathers information from Mobius's agent (mobiusdaemon) installed on each of your hosts. [Docs](https://mobiusmdm.com/docs/using-mobius/adding-hosts).

## Team

A team is a group of hosts. Organize hosts into teams to apply queries, policies, scripts, and other configurations tailored to their specific risk and compliance requirements. [Read the guide](https://mobiusmdm.com/guides/teams).

## Query

A query in Mobius refers to an osquery query. Osquery uses basic SQL commands to request data from hosts. Use queries to manage, monitor, and identify threats on your devices. [Docs](https://mobiusmdm.com/docs/using-mobius/mobius-ui).

## Policy

A policy is a specific “yes” or “no” query. Use policies to manage security compliance in your
organization. [Read the guide](https://mobiusmdm.com/securing/what-are-mobius-policies).

## Host vitals

Mobius's built-in queries for collecting and storing important device information.

## Software

Software in Mobius refers to the following:

- **Software library:** a collection of Mobius-maintained apps, VPP, and custom install packages that can be installed on your hosts. [See available software](https://mobiusmdm.com/app-library).
- **Software inventory** an inventory of each host’s installed software, including information about detected vulnerabilities (CVEs).

<meta name="pageOrderInSection" value="200">
