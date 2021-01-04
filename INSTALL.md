# Compiling TDC from source

## On Ubuntu 16.04 LTS

- *Optional:* make sure you are up to date.
```
sudo apt update && sudo apt upgrade
```

- Install the dependencies:
```
sudo apt-get install build-essential git autoconf libtool libssl-dev libboost-all-dev libdb++-dev libgmp-dev libminiupnpc-dev
```

- Clone this repository:
```
git clone https://github.com/neiros/TDC.git -b U16_TDC U16_TDC
```

- Build the source code:
```
cd U16_TDC/src/leveldb && chmod +x build_detect_platform && cd .. && make -f makefile.unix USE_UPNP=-
```

## Build TDC-qt

- Install the dependencies:
```
sudo apt install qt5-default qtcreator
```
Run Qt Creator and open the TDC-qt.pro file. An executable named TDC-qt will be built.