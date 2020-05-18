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
sudo apt-get install git cmake build-essential libssl-dev libboost-all-dev libdb++-dev
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
:construction: **This section is under development.** :construction:

- Install [Visual Studio](https://visualstudio.microsoft.com/vs/) with ```Desktop development with C++``` package.

- Install Git either through [official release](https://git-scm.com/downloads) either from Visual Studio's individual components section.

- Clone this repository: 

**Tip:** Use _Developer_ powershell/cmd instead of the default one.
```
git clone https://github.com/neiros/TDC
cd TDC
```

- Download and install [vcpkg package manager](https://github.com/microsoft/vcpkg):
```
git clone https://github.com/microsoft/vcpkg
cd vcpkg
.\bootstrap-vcpkg.bat
```

- Install dependencies:
```
.\vcpkg.exe install boost openssl berkeleydb
cd ..
```

- Generate Visual Studio solution files:
```
cmake -G "Visual Studio 2019" -DCMAKE_TOOLCHAIN_FILE=vcpkg\scripts\buildsystems\vcpkg.cmake
```

- Open the generated solution and build the project.

## on Mac OS

- Install the macOS command line tools:
```
xcode-select --install
```

- Then install [Homebrew](https://brew.sh).

- brew install cmake boost openssl 


berkeleydb


git clone

build