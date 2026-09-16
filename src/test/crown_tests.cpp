// Copyright (c) 2026-present The Crown developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crown/options.h>
#include <crown/validator.h>
#include <chainparams.h>
#include <init.h>
#include <test/util/setup_common.h>
#include <util/result.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <initializer_list>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(crown_tests, BasicTestingSetup)

namespace {

void ParseArgs(ArgsManager& args, std::initializer_list<const char*> extra_args)
{
    SetupServerArgs(args);
    std::vector<const char*> argv{"test"};
    argv.insert(argv.end(), extra_args.begin(), extra_args.end());
    std::string error;
    BOOST_REQUIRE(args.ParseParameters(argv.size(), argv.data(), error));
    BOOST_CHECK(error.empty());
}

} // namespace

BOOST_AUTO_TEST_CASE(crown_static_validator_math)
{
    const auto& validators = crown::GetStaticValidatorSet();
    BOOST_REQUIRE_EQUAL(validators.size(), 4U);
    BOOST_CHECK_EQUAL(validators[0].id, "validator-a");
    BOOST_CHECK_EQUAL(validators[1].id, "validator-b");
    BOOST_CHECK_EQUAL(validators[2].id, "validator-c");
    BOOST_CHECK_EQUAL(validators[3].id, "validator-d");
    for (const auto& validator : validators) BOOST_CHECK_EQUAL(validator.voting_power, 25);

    BOOST_CHECK_EQUAL(crown::TotalVotingPower(validators), 100);
    BOOST_CHECK_EQUAL(crown::QuorumThreshold(100), 67);
    BOOST_CHECK_EQUAL(crown::MaxFaultyVotingPower(100), 33);
    BOOST_CHECK(crown::HasQuorum(67, 100));
    BOOST_CHECK(crown::HasQuorum(75, 100));
    BOOST_CHECK(!crown::HasQuorum(66, 100));
    BOOST_CHECK(!crown::HasQuorum(50, 100));
}

BOOST_AUTO_TEST_CASE(crown_test_keys_match_static_validators)
{
    for (const auto& test_key : crown::GetStaticValidatorTestKeys()) {
        const auto* validator = crown::FindValidator(test_key.id);
        BOOST_REQUIRE(validator != nullptr);

        auto expected_pubkey = crown::DecodeValidatorPublicKey(validator->consensus_public_key_hex);
        BOOST_REQUIRE(expected_pubkey);

        auto private_key = crown::DecodeValidatorPrivateKey(test_key.private_key_hex);
        BOOST_REQUIRE(private_key);
        BOOST_CHECK(private_key->IsCompressed());
        BOOST_CHECK(private_key->GetPubKey() == *expected_pubkey);
    }
}

BOOST_AUTO_TEST_CASE(crown_runtime_options)
{
    ArgsManager non_validator_args;
    ParseArgs(non_validator_args, {"-crown"});
    auto crown_params = CreateChainParams(non_validator_args, ChainType::CROWN);
    auto runtime = crown::InitializeRuntimeOptions(non_validator_args, *crown_params);
    BOOST_REQUIRE(runtime);
    BOOST_CHECK(runtime->active);
    BOOST_CHECK(!runtime->validator);
    BOOST_CHECK(!runtime->local_validator.has_value());
    BOOST_CHECK_EQUAL(runtime->quorum_voting_power, 67);
    BOOST_CHECK_EQUAL(runtime->max_faulty_voting_power, 33);

    ArgsManager validator_args;
    ParseArgs(validator_args, {
        "-crown",
        "-crownvalidator=1",
        "-crownvalidatorid=validator-a",
        "-crownvalidatorprivkey=0000000000000000000000000000000000000000000000000000000000000001",
    });
    crown_params = CreateChainParams(validator_args, ChainType::CROWN);
    auto validator_runtime = crown::InitializeRuntimeOptions(validator_args, *crown_params);
    BOOST_REQUIRE(validator_runtime);
    BOOST_REQUIRE(validator_runtime->local_validator.has_value());
    BOOST_CHECK(validator_runtime->validator);
    BOOST_CHECK_EQUAL(validator_runtime->local_validator->id, "validator-a");
    BOOST_CHECK_EQUAL(HexStr(validator_runtime->local_validator->consensus_public_key), "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    BOOST_CHECK_EQUAL(validator_runtime->local_validator->voting_power, 25);
}

BOOST_AUTO_TEST_CASE(crown_invalid_validator_options)
{
    ArgsManager missing_args;
    ParseArgs(missing_args, {"-crown", "-crownvalidator=1"});
    auto validation = crown::ValidateOptions(missing_args, ChainType::CROWN);
    BOOST_CHECK(!validation);
    BOOST_CHECK_NE(util::ErrorString(validation).original.find("requires both -crownvalidatorid and -crownvalidatorprivkey"), std::string::npos);

    ArgsManager wrong_chain_args;
    ParseArgs(wrong_chain_args, {
        "-crownvalidator=1",
        "-crownvalidatorid=validator-a",
        "-crownvalidatorprivkey=0000000000000000000000000000000000000000000000000000000000000001",
    });
    auto wrong_chain_validation = crown::ValidateOptions(wrong_chain_args, ChainType::REGTEST);
    BOOST_CHECK(!wrong_chain_validation);
    BOOST_CHECK_NE(util::ErrorString(wrong_chain_validation).original.find("only supported on the experimental crown chain"), std::string::npos);

    ArgsManager mismatched_key_args;
    ParseArgs(mismatched_key_args, {
        "-crown",
        "-crownvalidator=1",
        "-crownvalidatorid=validator-a",
        "-crownvalidatorprivkey=0000000000000000000000000000000000000000000000000000000000000002",
    });
    const auto crown_params = CreateChainParams(mismatched_key_args, ChainType::CROWN);
    auto runtime = crown::InitializeRuntimeOptions(mismatched_key_args, *crown_params);
    BOOST_CHECK(!runtime);
    BOOST_CHECK_NE(util::ErrorString(runtime).original.find("does not match validator-a"), std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
