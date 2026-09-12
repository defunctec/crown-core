// Copyright (c) 2026 The Crown developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "arith_uint256.h"
#include "masternodeman.h"
#include "systemnodeman.h"

#include <boost/test/unit_test.hpp>

namespace
{
CTxIn MakeVin(uint64_t n)
{
    return CTxIn(COutPoint(ArithToUint256(n), 1));
}

CMasternode MakeMasternode(uint64_t n, const std::string& addr)
{
    CMasternode mn;
    mn.vin = MakeVin(n);
    mn.addr = CService(addr);
    mn.activeState = CMasternode::MASTERNODE_ENABLED;
    return mn;
}

CSystemnode MakeSystemnode(uint64_t n, const std::string& addr)
{
    CSystemnode sn;
    sn.vin = MakeVin(n);
    sn.addr = CService(addr);
    sn.activeState = CSystemnode::SYSTEMNODE_ENABLED;
    return sn;
}
} // namespace

BOOST_AUTO_TEST_SUITE(pr1_remediation_tests)

BOOST_AUTO_TEST_CASE(masternode_duplicate_ip_checks_ignore_same_vin)
{
    CMasternodeMan manager;
    CMasternode mn = MakeMasternode(1, "1.2.3.4:9340");

    BOOST_REQUIRE(manager.Add(mn));
    BOOST_CHECK(manager.IsAddressInUse(mn.addr));
    BOOST_CHECK(!manager.IsAddressInUse(mn.addr, mn.vin));
    BOOST_CHECK(manager.IsAddressInUse(mn.addr, MakeVin(2)));
    BOOST_CHECK(!manager.IsAddressInUse(CService("1.2.3.5:9340"), MakeVin(2)));
}

BOOST_AUTO_TEST_CASE(systemnode_duplicate_ip_checks_ignore_same_vin)
{
    CSystemnodeMan manager;
    CSystemnode sn = MakeSystemnode(1, "5.6.7.8:9340");

    BOOST_REQUIRE(manager.Add(sn));
    BOOST_CHECK(manager.IsAddressInUse(sn.addr));
    BOOST_CHECK(!manager.IsAddressInUse(sn.addr, sn.vin));
    BOOST_CHECK(manager.IsAddressInUse(sn.addr, MakeVin(2)));
    BOOST_CHECK(!manager.IsAddressInUse(CService("5.6.7.9:9340"), MakeVin(2)));
}

BOOST_AUTO_TEST_SUITE_END()
