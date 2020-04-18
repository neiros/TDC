# Compiling TDC from source

## Table of Contents
 - [Ubuntu](#on-ubuntu-16.04-lts)
 - [Windows 10](#on-windows-10)

## On Ubuntu 16.04 LTS

- *Optional:* make sure you are up to date.
```
sudo apt update && sudo apt upgrade
```

- Install the dependencies:
```
sudo apt-get install build-essential git autoconf libtool libssl-dev libboost-all-dev libdb++-dev libgmp-dev
```

- Clone this repository:
```
git clone https://github.com/neiros/TDC.git tdc
```

- Build the source code:
```
cd tdc/src
make -f makefile.unix USE_UPNP=-
```

## On Windows 10:
This section is under development. The easiest solution yet is to use WSL:

- [Install WSL](https://docs.microsoft.com/en-us/windows/wsl/install-win10)
- Choose [Ubuntu 16.04 LTS](https://www.microsoft.com/store/apps/9pjn388hp8c9) distro.
- Then refer to [Ubuntu-Manual](#on-ubuntu-16.04-lts) 