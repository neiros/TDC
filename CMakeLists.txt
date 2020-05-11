cmake_minimum_required(VERSION 3.9)

project(TDC-Core    VERSION 1.0 # TODO: modify this to provide actual version
                    DESCRIPTION "TDC Project. See: https://neiros.github.io/"
                    LANGUAGES C CXX )

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# enable CTest testing
enable_testing()

find_package(Boost REQUIRED COMPONENTS system filesystem program_options thread chrono unit_test_framework )
include_directories(SYSTEM ${Boost_INCLUDE_DIRS}) # not sure if i need this. Maybe Json to build json lib in v

find_package(OpenSSL)

# This is pointing to the folder FindBerkeleyDB, not the actual Cmake file
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(BerkeleyDB )

add_subdirectory(libs/json)
add_subdirectory(libs/leveldb) # VS generator sucks adding this to a solution
include_directories(libs/leveldb/helpers )   # workaround for memenv.h

add_subdirectory(libs/Lyra2RE)

add_subdirectory(src)

add_subdirectory(apps)


add_subdirectory(tests)
