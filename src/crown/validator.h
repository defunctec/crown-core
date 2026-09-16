// Copyright (c) 2026-present The Crown developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CROWN_VALIDATOR_H
#define BITCOIN_CROWN_VALIDATOR_H

#include <key.h>
#include <pubkey.h>
#include <util/result.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace crown {

struct StaticValidator {
    std::string_view id;
    std::string_view consensus_public_key_hex;
    int64_t voting_power;
};

struct TestValidatorPrivateKey {
    std::string_view id;
    std::string_view private_key_hex;
};

const std::array<StaticValidator, 4>& GetStaticValidatorSet();
const std::array<TestValidatorPrivateKey, 4>& GetStaticValidatorTestKeys();

const StaticValidator* FindValidator(std::string_view id);
const TestValidatorPrivateKey* FindTestValidatorPrivateKey(std::string_view id);

int64_t TotalVotingPower(std::span<const StaticValidator> validators);
int64_t QuorumThreshold(int64_t total_voting_power);
int64_t MaxFaultyVotingPower(int64_t total_voting_power);
bool HasQuorum(int64_t signed_voting_power, int64_t total_voting_power);

util::Result<CPubKey> DecodeValidatorPublicKey(std::string_view public_key_hex);
util::Result<CKey> DecodeValidatorPrivateKey(std::string_view private_key_hex);

} // namespace crown

#endif // BITCOIN_CROWN_VALIDATOR_H
