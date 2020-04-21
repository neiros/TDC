cmake_minimum_required(VERSION 3.9)

project(TDC-Core    VERSION 1.0 # TODO: modify this to provide actual version
                    DESCRIPTION "TDC Project. See: https://neiros.github.io/"
                    LANGUAGES C CXX )

find_package(Boost REQUIRED COMPONENTS system filesystem program_options thread chrono )
include_directories(SYSTEM ${Boost_INCLUDE_DIRS})


add_subdirectory(libs/json)
#add_subdirectory(libs/leveldb) # VS generator sucks adding this to a solution
add_subdirectory(libs/Lyra2RE)

add_subdirectory(src)

add_subdirectory(apps)
