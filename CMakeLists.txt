cmake_minimum_required(VERSION 3.9)

project(TDC-Core    VERSION 1.0 # TODO: modify this to provide actual version
                    DESCRIPTION "TDC Project. See: https://neiros.github.io/"
                    LANGUAGES C CXX )

add_subdirectory(libs/json)
add_subdirectory(libs/leveldb)
add_subdirectory(libs/Lyra2RE)

add_subdirectory(src)

add_subdirectory(apps)
