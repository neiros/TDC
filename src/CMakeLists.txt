file(GLOB CORE_SOURCES "*.cpp")
file(GLOB CORE_HEADERS "*.h")

add_library(TDC_Core ${CORE_SOURCES})

target_link_libraries(TDC_Core
                                Json
                                Lyra2RE )
#                                LevelDB )