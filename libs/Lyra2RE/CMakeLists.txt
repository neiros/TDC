file(GLOB LYRA2RE_LIB_SOURCES "*.c")
file(GLOB LYRA2RE_LIB_HEADERS "*.h")

# The headers are not compiled themselves, and the compiler will find them whenever they are included. 
# So, for a Makefile-based project, it does not make much sense to explicitly add them. 
# However, when we generate other things, e.g. MSVC project files, 
# we want to have the headers in those generated projects.
add_library(Lyra2RE ${LYRA2RE_LIB_SOURCES} 
                    ${LYRA2RE_LIB_HEADERS})

target_include_directories(Lyra2RE PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
