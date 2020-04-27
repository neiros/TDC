# Compiling TDC from source

## Table of Contents
 - [Ubuntu](#on-ubuntu)
 - [Windows 10](#on-windows-10)

## On Ubuntu

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
git clone https://github.com/neiros/TDC.git
cd TDC
```

- Build the source code:
```
mkdir build && cd build
cmake .. -G "Unix Makefiles" && make
```

- Built application will be written to ```/build/apps``` directory. 

## On Windows 10:
This section is under development.
