// Copyright (c) 2026-present The Crown developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CROWN_OPTIONS_H
#define BITCOIN_CROWN_OPTIONS_H

#include <key.h>
#include <pubkey.h>
#include <util/result.h>

#include <cstdint>
#include <optional>
#include <string>

class ArgsManager;
class CChainParams;
enum class ChainType;

namespace crown {

inline constexpr bool DEFAULT_CROWN_VALIDATOR{false};

struct LocalValidator {
    std::string id;
    CKey private_key;
    CPubKey consensus_public_key;
    int64_t voting_power;
};

struct RuntimeOptions {
    bool active{false};
    bool validator{false};
    int64_t total_voting_power{0};
    int64_t quorum_voting_power{0};
    int64_t max_faulty_voting_power{0};
    std::optional<LocalValidator> local_validator;
};

void SetupArgs(ArgsManager& argsman);
util::Result<void> ValidateOptions(const ArgsManager& args, ChainType chain);
util::Result<RuntimeOptions> InitializeRuntimeOptions(const ArgsManager& args, const CChainParams& chainparams);

} // namespace crown

#endif // BITCOIN_CROWN_OPTIONS_H
