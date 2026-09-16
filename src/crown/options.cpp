// Copyright (c) 2026-present The Crown developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crown/options.h>

#include <chainparams.h>
#include <common/args.h>
#include <crown/validator.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <string>

namespace crown {
namespace {

constexpr auto ARG_VALIDATOR{"-crownvalidator"};
constexpr auto ARG_VALIDATOR_ID{"-crownvalidatorid"};
constexpr auto ARG_VALIDATOR_PRIVKEY{"-crownvalidatorprivkey"};

util::Result<void> ValidateValidatorFlagValue(const ArgsManager& args)
{
    if (!args.IsArgSet(ARG_VALIDATOR)) return {};
    const std::string value{args.GetArg(ARG_VALIDATOR, "")};
    if (value.empty() || value == "1" || value == "0") return {};
    return util::Error{Untranslated("Crown validator mode only accepts -crownvalidator=1 or -crownvalidator=0.")};
}

bool HasValidatorConfig(const ArgsManager& args)
{
    return args.GetBoolArg(ARG_VALIDATOR, DEFAULT_CROWN_VALIDATOR) ||
           args.IsArgSet(ARG_VALIDATOR_ID) ||
           args.IsArgSet(ARG_VALIDATOR_PRIVKEY);
}

util::Result<void> ValidateValidatorKeyStructure(const ArgsManager& args)
{
    const std::string key_hex{args.GetArg(ARG_VALIDATOR_PRIVKEY, "")};
    if (!IsHex(key_hex) || key_hex.size() != 64) {
        return util::Error{Untranslated("Crown validator mode requires -crownvalidatorprivkey to be 32-byte hex.")};
    }
    return {};
}

} // namespace

void SetupArgs(ArgsManager& argsman)
{
    argsman.AddArg(std::string{ARG_VALIDATOR} + "=<0|1>", "Enable static validator mode on the experimental crown chain (default: 0). When disabled, the node runs as a non-validator full node.", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_ELISION | ArgsManager::DISALLOW_NEGATION | ArgsManager::NETWORK_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg(std::string{ARG_VALIDATOR_ID} + "=<id>", "Static validator identifier for the experimental crown chain (validator-a, validator-b, validator-c, validator-d). Requires -crownvalidator=1.", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION | ArgsManager::NETWORK_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg(std::string{ARG_VALIDATOR_PRIVKEY} + "=<hex>", "32-byte hex validator private key for the experimental crown chain. TEST ONLY, PUBLICLY KNOWN, NEVER USE FOR MAINNET. Requires -crownvalidator=1.", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION | ArgsManager::NETWORK_ONLY | ArgsManager::SENSITIVE, OptionsCategory::CHAINPARAMS);
}

util::Result<void> ValidateOptions(const ArgsManager& args, const ChainType chain)
{
    if (auto flag_check = ValidateValidatorFlagValue(args); !flag_check) return flag_check;

    if (chain != ChainType::CROWN) {
        if (HasValidatorConfig(args)) {
            return util::Error{Untranslated("Crown validator options are only supported on the experimental crown chain (-chain=crown or -crown).")};
        }
        return {};
    }

    const bool validator{args.GetBoolArg(ARG_VALIDATOR, DEFAULT_CROWN_VALIDATOR)};
    const bool has_id{args.IsArgSet(ARG_VALIDATOR_ID)};
    const bool has_privkey{args.IsArgSet(ARG_VALIDATOR_PRIVKEY)};

    if (!validator) {
        if (has_id || has_privkey) {
            return util::Error{Untranslated("Crown validator identity and key options require -crownvalidator=1.")};
        }
        return {};
    }

    if (!has_id || !has_privkey) {
        return util::Error{Untranslated("Crown validator mode requires both -crownvalidatorid and -crownvalidatorprivkey.")};
    }

    const std::string validator_id{args.GetArg(ARG_VALIDATOR_ID, "")};
    if (validator_id.empty()) {
        return util::Error{Untranslated("Crown validator mode requires a non-empty -crownvalidatorid.")};
    }
    if (!FindValidator(validator_id)) {
        return util::Error{Untranslated(strprintf("Unknown Crown validator id '%s'. Expected one of validator-a, validator-b, validator-c, validator-d.", validator_id))};
    }

    return ValidateValidatorKeyStructure(args);
}

util::Result<RuntimeOptions> InitializeRuntimeOptions(const ArgsManager& args, const CChainParams& chainparams)
{
    RuntimeOptions options;
    options.active = chainparams.GetChainType() == ChainType::CROWN;
    options.total_voting_power = TotalVotingPower(GetStaticValidatorSet());
    options.quorum_voting_power = QuorumThreshold(options.total_voting_power);
    options.max_faulty_voting_power = MaxFaultyVotingPower(options.total_voting_power);

    if (!options.active) return options;

    if (auto validation = ValidateOptions(args, chainparams.GetChainType()); !validation) {
        return util::Error{util::ErrorString(validation)};
    }
    if (!args.GetBoolArg(ARG_VALIDATOR, DEFAULT_CROWN_VALIDATOR)) return options;

    const std::string validator_id{args.GetArg(ARG_VALIDATOR_ID, "")};
    const StaticValidator* validator = FindValidator(validator_id);
    if (!validator) {
        return util::Error{Untranslated(strprintf("Unknown Crown validator id '%s'.", validator_id))};
    }

    auto configured_pubkey = DecodeValidatorPublicKey(validator->consensus_public_key_hex);
    if (!configured_pubkey) return util::Error{util::ErrorString(configured_pubkey)};

    auto private_key = DecodeValidatorPrivateKey(args.GetArg(ARG_VALIDATOR_PRIVKEY, ""));
    if (!private_key) return util::Error{util::ErrorString(private_key)};

    const CPubKey derived_pubkey = private_key->GetPubKey();
    if (derived_pubkey != *configured_pubkey) {
        return util::Error{Untranslated(strprintf("Configured Crown validator private key does not match %s.", validator_id))};
    }

    options.validator = true;
    options.local_validator = LocalValidator{
        .id = validator_id,
        .private_key = *private_key,
        .consensus_public_key = derived_pubkey,
        .voting_power = validator->voting_power,
    };
    return options;
}

} // namespace crown
