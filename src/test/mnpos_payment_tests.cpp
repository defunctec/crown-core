#include "key.h"
#include "main.h"
#include "masternode-payments.h"
#include "masternodeman.h"
#include "script/standard.h"
#include "systemnode-payments.h"
#include "systemnodeman.h"

#include <boost/test/unit_test.hpp>

namespace {

CScript MakePayeeScript()
{
    CKey key;
    key.MakeNewKey(true);
    return GetScriptForDestination(key.GetPubKey().GetID());
}

struct PaymentStateGuard
{
    PaymentStateGuard()
    {
        masternodePayments.Clear();
        systemnodePayments.Clear();
        mnodeman.Clear();
        snodeman.Clear();
    }

    ~PaymentStateGuard()
    {
        masternodePayments.Clear();
        systemnodePayments.Clear();
        mnodeman.Clear();
        snodeman.Clear();
    }
};

void AddMasternodePayee(int nHeight, const CScript& payee)
{
    CMasternodeBlockPayees blockPayees(nHeight);
    blockPayees.AddPayee(payee, MNPAYMENTS_SIGNATURES_REQUIRED);
    masternodePayments.mapMasternodeBlocks[nHeight] = blockPayees;
}

void AddSystemnodePayee(int nHeight, const CScript& payee)
{
    CSystemnodeBlockPayees blockPayees(nHeight);
    blockPayees.AddPayee(payee, SNPAYMENTS_SIGNATURES_REQUIRED);
    systemnodePayments.mapSystemnodeBlocks[nHeight] = blockPayees;
}

CMutableTransaction CreateCoinbaseTemplate()
{
    CMutableTransaction tx;
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return tx;
}

} // namespace

BOOST_AUTO_TEST_SUITE(mnpos_payment_tests)

BOOST_AUTO_TEST_CASE(coinbase_outputs_with_masternode_and_systemnode_payees)
{
    PaymentStateGuard guard;

    const int nHeight = chainActive.Tip()->nHeight + 1;
    const CAmount nFees = 0;
    const CAmount blockValue = GetBlockValue(chainActive.Tip()->nHeight, nFees);
    const CAmount masternodePayment = GetMasternodePayment(nHeight, blockValue);
    const CAmount systemnodePayment = GetSystemnodePayment(nHeight, blockValue);
    const CScript masternodeScript = MakePayeeScript();
    const CScript systemnodeScript = MakePayeeScript();

    AddMasternodePayee(nHeight, masternodeScript);
    AddSystemnodePayee(nHeight, systemnodeScript);

    CMutableTransaction tx = CreateCoinbaseTemplate();
    FillBlockPayee(tx, nFees);
    SNFillBlockPayee(tx, nFees);

    BOOST_CHECK_EQUAL(tx.vout.size(), 3U);
    BOOST_CHECK_EQUAL(tx.vout[0].nValue, blockValue - masternodePayment - systemnodePayment);
    BOOST_CHECK(tx.vout[MN_PMT_SLOT] == CTxOut(masternodePayment, masternodeScript));
    BOOST_CHECK(tx.vout[SN_PMT_SLOT] == CTxOut(systemnodePayment, systemnodeScript));
    BOOST_CHECK_EQUAL(CTransaction(tx).GetValueOut(), blockValue);
}

BOOST_AUTO_TEST_CASE(coinbase_outputs_with_masternode_payee_only)
{
    PaymentStateGuard guard;

    const int nHeight = chainActive.Tip()->nHeight + 1;
    const CAmount nFees = 0;
    const CAmount blockValue = GetBlockValue(chainActive.Tip()->nHeight, nFees);
    const CAmount masternodePayment = GetMasternodePayment(nHeight, blockValue);
    const CScript masternodeScript = MakePayeeScript();

    AddMasternodePayee(nHeight, masternodeScript);

    CMutableTransaction tx = CreateCoinbaseTemplate();
    FillBlockPayee(tx, nFees);
    SNFillBlockPayee(tx, nFees);

    BOOST_CHECK_EQUAL(tx.vout.size(), 2U);
    BOOST_CHECK_EQUAL(tx.vout[0].nValue, blockValue - masternodePayment);
    BOOST_CHECK(tx.vout[MN_PMT_SLOT] == CTxOut(masternodePayment, masternodeScript));
    BOOST_CHECK_EQUAL(CTransaction(tx).GetValueOut(), blockValue);
}

BOOST_AUTO_TEST_CASE(coinbase_outputs_with_systemnode_payee_only)
{
    PaymentStateGuard guard;

    const int nHeight = chainActive.Tip()->nHeight + 1;
    const CAmount nFees = 0;
    const CAmount blockValue = GetBlockValue(chainActive.Tip()->nHeight, nFees);
    const CAmount systemnodePayment = GetSystemnodePayment(nHeight, blockValue);
    const CScript systemnodeScript = MakePayeeScript();

    AddSystemnodePayee(nHeight, systemnodeScript);

    CMutableTransaction tx = CreateCoinbaseTemplate();
    FillBlockPayee(tx, nFees);
    SNFillBlockPayee(tx, nFees);

    BOOST_CHECK_EQUAL(tx.vout.size(), 3U);
    BOOST_CHECK_EQUAL(tx.vout[0].nValue, blockValue - systemnodePayment);
    BOOST_CHECK(tx.vout[MN_PMT_SLOT] == CTxOut(0, CScript()));
    BOOST_CHECK(tx.vout[SN_PMT_SLOT] == CTxOut(systemnodePayment, systemnodeScript));
    BOOST_CHECK_NO_THROW(CTransaction(tx).GetValueOut());
    BOOST_CHECK_EQUAL(CTransaction(tx).GetValueOut(), blockValue);
}

BOOST_AUTO_TEST_CASE(coinbase_outputs_with_no_node_payees)
{
    PaymentStateGuard guard;

    const CAmount nFees = 0;
    const CAmount blockValue = GetBlockValue(chainActive.Tip()->nHeight, nFees);

    CMutableTransaction tx = CreateCoinbaseTemplate();
    FillBlockPayee(tx, nFees);
    SNFillBlockPayee(tx, nFees);

    BOOST_CHECK_EQUAL(tx.vout.size(), 1U);
    BOOST_CHECK_EQUAL(tx.vout[0].nValue, blockValue);
    BOOST_CHECK_EQUAL(CTransaction(tx).GetValueOut(), blockValue);
}

BOOST_AUTO_TEST_SUITE_END()
