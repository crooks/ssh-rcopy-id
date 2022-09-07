# ssh-rcopy-id

Copy user public keys using root privileges

**Warning**: This code is expected to be executed by a user with root privileges.  You should review the source code and test it on an isolated host before unleashing it on your valuable server estate!

## Overview
In a corporate IT environment with a mixture of Linux and Unix platforms, it's frequently painful to manage SSH public keys and associated authorized_keys files on workstations and servers.  This program attempts to ease the pain by allowing a bastion host with root access to other servers to deploy keys on behalf of end users.

## Installation
* Clone the Git repository
* Run `go build` from within the repo
* Move the resulting binary to a location like `/usr/local/sbin`
* Test it with `ssh-rcopy-id --help`

## Usage
The following is a basic usage summary.  See the `--help` for details of other configuration options.

* Create a subdirectory for the utility (E.g. `/root/rcopy`)
* Copy (or create) the config file (`/root/rcopy/ssh-rcopy-id.yml`)
  * As a minimum, add the keys root will use to authenticate to the destination servers.
* Create a subdirectory for holding the user's public keys (E.g. `/root/rcopy/pubkeys`)
* Populate the pubkeys directory with the keys you want to deploy.
  * The file name is important!  It should be `<username>.auth`.
  * The extension `auth` is used in preference to `pub` to avoid confusion; The file might contain multiple public keys.  The content will be deployed as `~/.ssh/authorized_keys`.
* Change directory to `/root/rcopy` and run `ssh-rcopy-id --hosts=<host1>,<host2>`.