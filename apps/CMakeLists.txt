add_executable(TDC_Daemon bitcoind.cpp)

target_link_libraries(TDC_Daemon PRIVATE 
										TDC_Core) 
										# TODO: Add Boost library. Boost::algorithm if i'm not mistaken