file(GLOB TEST_SOURCES "*.cpp")

# Add a testing executable
add_executable(unit_tests ${TEST_SOURCES})

target_link_libraries(unit_tests
                                    TDC_Core
                                    ${Boost_LIBRARIES}
                                    ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY} )

target_compile_definitions(unit_tests
                                    PRIVATE
                                    BOOST_TEST_DYN_LINK )

add_test(test_all unit_tests)

#copy data files needed for tests from source dir to where unit_tests will be executed.
FILE(GLOB TestData data/*)
file(COPY
        ${TestData}
        DESTINATION data)
