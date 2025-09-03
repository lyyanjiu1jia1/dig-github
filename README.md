# GitHub Hosts Updater

This script automatically resolves the IP address of github.com using the `dig` command and updates the `/etc/hosts` file with the resolved IP address. It helps ensure that your system can connect to GitHub even when DNS resolution is problematic.

## Features

- Resolves github.com IP address using `dig`
- Checks if github.com already exists in `/etc/hosts` to avoid duplicates
- Automatically adds the entry if not present
- Creates a backup of `/etc/hosts` before making changes
- Flushes DNS cache after updating hosts file

## Prerequisites

- Python 3.x
- `dig` command-line tool (usually included with DNS utilities)
- sudo privileges (required for modifying `/etc/hosts`)

## Usage

1. Run the script:
   ```bash
   python main.py