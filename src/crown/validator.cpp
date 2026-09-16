// Copyright (c) 2026-present The Crown developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crown/validator.h>

#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <algorithm>
#include <array>
#include <vector>

namespace crown {
namespace {

constexpr std::array<StaticValidator, 4> STATIC_VALIDATORS{{
    {"validator-a", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 25},
    {"validator-b", "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", 25},
    {"validator-c", "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", 25},
    {"validator-d", "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13", 25},
}};

// TEST ONLY / PUBLICLY KNOWN / NEVER USE FOR MAINNET.
constexpr std::array<TestValidatorPrivateKey, 4> STATIC_TEST_KEYS{{
    {"validator-a", "0000000000000000000000000000000000000000000000000000000000000001"},
    {"validator-b", "0000000000000000000000000000000000000000000000000000000000000002"},
    {"validator-c", "0000000000000000000000000000000000000000000000000000000000000003"},
    {"validator-d", "0000000000000000000000000000000000000000000000000000000000000004"},
}};

} // namespace

const std::array<StaticValidator, 4>& GetStaticValidatorSet()
{
    return STATIC_VALIDATORS;
}

const std::array<TestValidatorPrivateKey, 4>& GetStaticValidatorTestKeys()
{
    return STATIC_TEST_KEYS;
}

const StaticValidator* FindValidator(const std::string_view id)
{
    const auto it = std::ranges::find(STATIC_VALIDATORS, id, &StaticValidator::id);
    return it == STATIC_VALIDATORS.end() ? nullptr : &*it;
}

const TestValidatorPrivateKey* FindTestValidatorPrivateKey(const std::string_view id)
{
    const auto it = std::ranges::find(STATIC_TEST_KEYS, id, &TestValidatorPrivateKey::id);
    return it == STATIC_TEST_KEYS.end() ? nullptr : &*it;
}

int64_t TotalVotingPower(const std::span<const StaticValidator> validators)
{
    int64_t total{0};
    for (const auto& validator : validators) total += validator.voting_power;
    return total;
}

int64_t QuorumThreshold(const int64_t total_voting_power)
{
    return total_voting_power <= 0 ? 0 : ((2 * total_voting_power) / 3) + 1;
}

int64_t MaxFaultyVotingPower(const int64_t total_voting_power)
{
    return total_voting_power <= 0 ? 0 : total_voting_power - QuorumThreshold(total_voting_power);
}

bool HasQuorum(const int64_t signed_voting_power, const int64_t total_voting_power)
{
    return signed_voting_power >= QuorumThreshold(total_voting_power);
}

util::Result<CPubKey> DecodeValidatorPublicKey(const std::string_view public_key_hex)
{
    if (!IsHex(public_key_hex)) {
        return util::Error{Untranslated(strprintf("Invalid Crown validator public key '%s': expected hex.", public_key_hex))};
    }
    const std::vector<unsigned char> bytes = ParseHex(public_key_hex);
    if (bytes.size() != CPubKey::COMPRESSED_SIZE) {
        return util::Error{Untranslated(strprintf("Invalid Crown validator public key '%s': expected %u-byte compressed secp256k1 key.", public_key_hex, CPubKey::COMPRESSED_SIZE))};
    }
    const CPubKey pubkey{bytes.begin(), bytes.end()};
    if (!pubkey.IsFullyValid()) {
        return util::Error{Untranslated(strprintf("Invalid Crown validator public key '%s': secp256k1 validation failed.", public_key_hex))};
    }
    return pubkey;
}

util::Result<CKey> DecodeValidatorPrivateKey(const std::string_view private_key_hex)
{
    if (!IsHex(private_key_hex) || private_key_hex.size() != 64) {
        return util::Error{Untranslated("Invalid Crown validator private key: expected 32-byte hex.")};
    }
    const std::vector<unsigned char> bytes = ParseHex(private_key_hex);
    if (bytes.size() != 32) {
        return util::Error{Untranslated("Invalid Crown validator private key: expected 32-byte hex.")};
    }
    CKey key;
    key.Set(bytes.begin(), bytes.end(), /*fCompressedIn=*/true);
    if (!key.IsValid()) {
        return util::Error{Untranslated("Invalid Crown validator private key: secp256k1 validation failed.")};
    }
    return key;
}

} // namespace crown
