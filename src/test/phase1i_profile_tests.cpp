// Copyright (c) 2026 The Crown developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "main.h"
#include "masternode.h"
#include "systemnode.h"
#include "util.h"
#include "wallet.h"

#include <boost/test/unit_test.hpp>

namespace
{
class ScopedArgValue
{
public:
    explicit ScopedArgValue(const std::string& key)
        : key_(key), hadOriginal_(false)
    {
        std::map<std::string, std::string>::const_iterator it = mapArgs.find(key_);
        if (it != mapArgs.end()) {
            hadOriginal_ = true;
            original_ = it->second;
        }
    }

    ~ScopedArgValue()
    {
        if (hadOriginal_) {
            mapArgs[key_] = original_;
        } else {
            mapArgs.erase(key_);
        }
    }

private:
    std::string key_;
    bool hadOriginal_;
    std::string original_;
};
} // namespace

BOOST_AUTO_TEST_SUITE(phase1i_profile_tests)

BOOST_AUTO_TEST_CASE(production_rules_unchanged)
{
    BOOST_CHECK_EQUAL(MASTERNODE_COLLATERAL, 10000);
    BOOST_CHECK_EQUAL(SYSTEMNODE_COLLATERAL, 500);
    BOOST_CHECK_EQUAL(MASTERNODE_MIN_CONFIRMATIONS, 15);
    BOOST_CHECK_EQUAL(SYSTEMNODE_MIN_CONFIRMATIONS, 15);

    BOOST_CHECK_EQUAL(Params(CBaseChainParams::MAIN).PoSStartHeight(), 2330000);
    BOOST_CHECK_EQUAL(Params(CBaseChainParams::MAIN).SubsidyHalvingInterval(), 2100000);
    BOOST_CHECK_EQUAL(Params(CBaseChainParams::TESTNET).PoSStartHeight(), 141000);
    BOOST_CHECK_EQUAL(Params(CBaseChainParams::TESTNET).SubsidyHalvingInterval(), 130000);

    SelectParams(CBaseChainParams::MAIN);
    BOOST_CHECK_EQUAL(GetSubsidy(0, 0), 12 * COIN);
    BOOST_CHECK_EQUAL(GetSubsidy(2099999, 0), 12 * COIN);
    BOOST_CHECK_EQUAL(GetSubsidy(2100000, 0), 6 * COIN);
    BOOST_CHECK_EQUAL(GetSubsidy(2329999, 0), 6 * COIN);
    BOOST_CHECK_EQUAL(GetSubsidy(2330000, 0), 5 * COIN);

    SelectParams(CBaseChainParams::UNITTEST);
}

BOOST_AUTO_TEST_CASE(regtest_fast_profile_overrides_are_regtest_only)
{
    ScopedArgValue halvingArg("-regtestsubsidyhalvinginterval");
    ScopedArgValue posArg("-regtestposstartheight");

    SelectParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(Params().SubsidyHalvingInterval(), 150);
    BOOST_CHECK_EQUAL(Params().PoSStartHeight(), 141000);

    mapArgs["-regtestsubsidyhalvinginterval"] = "2100000";
    mapArgs["-regtestposstartheight"] = "1050";
    SelectParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(Params().SubsidyHalvingInterval(), 2100000);
    BOOST_CHECK_EQUAL(Params().PoSStartHeight(), 1050);

    BOOST_CHECK_EQUAL(Params(CBaseChainParams::MAIN).SubsidyHalvingInterval(), 2100000);
    BOOST_CHECK_EQUAL(Params(CBaseChainParams::MAIN).PoSStartHeight(), 2330000);
    BOOST_CHECK_EQUAL(Params(CBaseChainParams::TESTNET).SubsidyHalvingInterval(), 130000);
    BOOST_CHECK_EQUAL(Params(CBaseChainParams::TESTNET).PoSStartHeight(), 141000);

    mapArgs.erase("-regtestsubsidyhalvinginterval");
    mapArgs.erase("-regtestposstartheight");
    SelectParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(Params().SubsidyHalvingInterval(), 150);
    BOOST_CHECK_EQUAL(Params().PoSStartHeight(), 141000);

    SelectParams(CBaseChainParams::UNITTEST);
}

BOOST_AUTO_TEST_SUITE_END()
