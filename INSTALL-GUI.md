:construction: Work in progress. :construction:

## On Ubuntu 16.04 LTS

- *Optional:* make sure you are up to date.
```
sudo apt update && sudo apt upgrade
```

- Install the dependencies:
```
sudo apt-get install build-essential git autoconf libtool libssl-dev libboost-all-dev libdb++-dev libgmp-dev qt4-qmake libqt4-dev
```

- Clone this repository:
```
git clone https://github.com/neiros/TDC.git tdc
```

- Build the source code:
```
cd tdc
qmake TDC-qt.pro USE_UPNP=-
make
```


