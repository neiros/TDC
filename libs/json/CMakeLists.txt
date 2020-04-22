file(GLOB JSON_LIB_SOURCES "*.cpp")
file(GLOB JSON_LIB_HEADERS "*.h")

# The headers are not compiled themselves, and the compiler will find them whenever they are included. 
# So, for a Makefile-based project, it does not make much sense to explicitly add them. 
# However, when we generate other things, e.g. MSVC project files, 
# we want to have the headers in those generated projects.
add_library(Json    ${JSON_LIB_SOURCES} 
                    ${JSON_LIB_HEADERS})

target_include_directories(Json PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
