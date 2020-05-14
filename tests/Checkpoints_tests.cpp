//
// Unit tests for block-chain checkpoints
//
#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/test/unit_test.hpp>
#include <boost/foreach.hpp>

#include "checkpoints.h"
#include "Helpers/util.h"

using namespace std;

BOOST_AUTO_TEST_SUITE(Checkpoints_tests)

BOOST_AUTO_TEST_CASE(sanity)
{
    uint256 p20000 = uint256("0x0000003bcec9382c0cc9c59871fc41f64f085194a5fa36853d9d98c592b58d52");
    uint256 p222222 = uint256("0x000000034ac37950fc67fc42bb5c2e83479ff237f931d5e275ebc11ff9e236de");
    BOOST_CHECK(Checkpoints::CheckBlock(20000, p20000));
    BOOST_CHECK(Checkpoints::CheckBlock(222222, p222222));

    
    // Wrong hashes at checkpoints should fail:
    BOOST_CHECK(!Checkpoints::CheckBlock(20000, p222222));
    BOOST_CHECK(!Checkpoints::CheckBlock(222222, p20000));

    // ... but any hash not at a checkpoint should succeed:
    BOOST_CHECK(Checkpoints::CheckBlock(20000+1, p222222));
    BOOST_CHECK(Checkpoints::CheckBlock(222222+1, p20000));

    BOOST_CHECK(Checkpoints::GetTotalBlocksEstimate() >= 222222);
}    

BOOST_AUTO_TEST_SUITE_END()
