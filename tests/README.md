The sources in this directory are unit test cases.  Boost includes a
unit testing framework, and since bitcoin already uses boost, it makes
sense to simply use this framework rather than require developers to
configure some other framework (we want as few impediments to creating
unit tests as possible).

The build system is setup to compile an executable called "test_bitcoin"
that runs all of the unit tests.  The main source file is called
test_bitcoin.cpp, which simply includes other files that contain the
actual unit tests (outside of a couple required preprocessor
directives).  The pattern is to create one test file for each class or
source file for which you want to create unit tests.  The file naming
convention is "<source_filename>_tests.cpp" and such files should wrap
their tests in a test suite called "<source_filename>_tests".  For an
examples of this pattern, examine uint160_tests.cpp and
uint256_tests.cpp.


Compiling/running tdcoind unit tests
------------------------------------

To compile and run the tests:

	cd src
	make -f makefile.unix test_tdcoin USE_UPNP=- # Replace makefile.unix if you're not on unix
	./test_tdcoin   # Runs the unit tests

If all tests succeed the last line of output will be:
`*** No errors detected`

To add more tests, add `BOOST_AUTO_TEST_CASE` functions to the existing
.cpp files in the test/ directory or add new .cpp files that
implement new BOOST_AUTO_TEST_SUITE sections (the makefiles are
set up to add test/*.cpp to test_tdcoin automatically).