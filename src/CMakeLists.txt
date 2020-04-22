file(GLOB CORE_SOURCES "*.cpp")
file(GLOB CORE_HEADERS "*.h")

add_library(TDC_Core ${CORE_SOURCES})

target_link_libraries(TDC_Core
                                Json
                                Lyra2RE 
                                leveldb 
                                Boost::system 
                                Boost::filesystem
                                Boost::thread
                                Boost::program_options
                                ${OPENSSL_LIBRARIES} 
                                Oracle::BerkeleyDB )

# I don't know what headers do we need therefore provide all 
target_include_directories(TDC_Core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
