file(GLOB JSON_LIB_SOURCES "*.cpp")
file(GLOB JSON_LIB_HEADERS "*.h")

# By default MSVC has a 2^16 limit on the number of sections in an object file,
# and this needs more than that.
if (MSVC)
  set_source_files_properties(${JSON_LIB_SOURCES} PROPERTIES COMPILE_FLAGS /bigobj)
endif()

# The headers are not compiled themselves, and the compiler will find them whenever they are included. 
# So, for a Makefile-based project, it does not make much sense to explicitly add them. 
# However, when we generate other things, e.g. MSVC project files, 
# we want to have the headers in those generated projects.
add_library(Json    ${JSON_LIB_SOURCES} 
                    ${JSON_LIB_HEADERS})

target_include_directories(Json PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(Json ${BOOST_LIBRARIES})