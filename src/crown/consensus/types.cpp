// Copyright (c) 2026-present The Crown developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crown/consensus/types.h>

#include <hash.h>
#include <pubkey.h>
#include <tinyformat.h>
#include <util/result.h>
#include <util/translation.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace crown::consensus {
namespace {

constexpr std::string_view PROPOSAL_SIGN_DOMAIN{"crown-consensus-proposal-v1"};
constexpr std::string_view VOTE_SIGN_DOMAIN{"crown-consensus-vote-v1"};

void WriteOptionalBlock(HashWriter& writer, const std::optional<BlockID>& block_id)
{
    writer << static_cast<uint8_t>(block_id.has_value());
    if (block_id) writer << *block_id;
}

const StaticValidator* FindValidatorInSet(std::span<const StaticValidator> validators, const std::string_view id)
{
    for (const auto& validator : validators) {
        if (validator.id == id) return &validator;
    }
    return nullptr;
}

util::Result<CPubKey> DecodeKnownValidatorKey(std::span<const StaticValidator> validators, const std::string_view id)
{
    const StaticValidator* validator = FindValidatorInSet(validators, id);
    if (!validator) {
        return util::Error{Untranslated(strprintf("Unknown Crown validator '%s'.", id))};
    }
    return DecodeValidatorPublicKey(validator->consensus_public_key_hex);
}

template <typename Message>
util::Result<void> SignMessage(const uint256& hash, Message& message, const CKey& private_key)
{
    message.signature.clear();
    if (!private_key.Sign(hash, message.signature)) {
        return util::Error{Untranslated("Failed to sign Crown consensus message.")};
    }
    return {};
}

} // namespace

std::string_view StepName(const Step step)
{
    switch (step) {
    case Step::PROPOSE:
        return "PROPOSE";
    case Step::PREVOTE:
        return "PREVOTE";
    case Step::PRECOMMIT:
        return "PRECOMMIT";
    case Step::COMMIT:
        return "COMMIT";
    }
    return "UNKNOWN";
}

std::string_view VoteTypeName(const VoteType type)
{
    switch (type) {
    case VoteType::PREVOTE:
        return "PREVOTE";
    case VoteType::PRECOMMIT:
        return "PRECOMMIT";
    }
    return "UNKNOWN";
}

std::string_view TimeoutName(const TimeoutKind timeout)
{
    switch (timeout) {
    case TimeoutKind::PROPOSE:
        return "PROPOSE_TIMEOUT";
    case TimeoutKind::PREVOTE:
        return "PREVOTE_TIMEOUT";
    case TimeoutKind::PRECOMMIT:
        return "PRECOMMIT_TIMEOUT";
    }
    return "UNKNOWN";
}

bool SameProposalPayload(const Proposal& lhs, const Proposal& rhs)
{
    return lhs.height == rhs.height &&
           lhs.round == rhs.round &&
           lhs.proposer_id == rhs.proposer_id &&
           lhs.block_id == rhs.block_id &&
           lhs.valid_round == rhs.valid_round;
}

bool SameVotePayload(const Vote& lhs, const Vote& rhs)
{
    return lhs.type == rhs.type &&
           lhs.height == rhs.height &&
           lhs.round == rhs.round &&
           lhs.validator_id == rhs.validator_id &&
           lhs.block_id == rhs.block_id;
}

bool VotesConflict(const Vote& lhs, const Vote& rhs)
{
    return lhs.type == rhs.type &&
           lhs.height == rhs.height &&
           lhs.round == rhs.round &&
           lhs.validator_id == rhs.validator_id &&
           lhs.block_id != rhs.block_id;
}

uint256 ProposalSigningHash(const Proposal& proposal)
{
    HashWriter writer{};
    writer << std::string{PROPOSAL_SIGN_DOMAIN}
           << proposal.height
           << proposal.round
           << proposal.proposer_id
           << proposal.valid_round;
    WriteOptionalBlock(writer, proposal.block_id);
    return writer.GetHash();
}

uint256 VoteSigningHash(const Vote& vote)
{
    HashWriter writer{};
    writer << std::string{VOTE_SIGN_DOMAIN}
           << static_cast<uint8_t>(vote.type)
           << vote.height
           << vote.round
           << vote.validator_id;
    WriteOptionalBlock(writer, vote.block_id);
    return writer.GetHash();
}

util::Result<void> SignProposal(Proposal& proposal, const CKey& private_key)
{
    return SignMessage(ProposalSigningHash(proposal), proposal, private_key);
}

util::Result<void> SignVote(Vote& vote, const CKey& private_key)
{
    return SignMessage(VoteSigningHash(vote), vote, private_key);
}

util::Result<void> VerifyProposalSignature(const Proposal& proposal, const std::span<const StaticValidator> validators)
{
    if (proposal.proposer_id.empty()) {
        return util::Error{Untranslated("Malformed Crown proposal: missing proposer id.")};
    }
    if (!proposal.block_id.has_value()) {
        return util::Error{Untranslated("Malformed Crown proposal: missing block id.")};
    }
    if (proposal.round < 0) {
        return util::Error{Untranslated("Malformed Crown proposal: negative round.")};
    }
    if (proposal.valid_round < NO_VALID_ROUND) {
        return util::Error{Untranslated("Malformed Crown proposal: invalid valid_round.")};
    }
    auto pubkey = DecodeKnownValidatorKey(validators, proposal.proposer_id);
    if (!pubkey) return util::Error{util::ErrorString(pubkey)};
    if (proposal.signature.empty() || !pubkey->Verify(ProposalSigningHash(proposal), proposal.signature)) {
        return util::Error{Untranslated(strprintf("Invalid Crown proposal signature from '%s'.", proposal.proposer_id))};
    }
    return {};
}

util::Result<void> VerifyVoteSignature(const Vote& vote, const std::span<const StaticValidator> validators)
{
    if (vote.validator_id.empty()) {
        return util::Error{Untranslated("Malformed Crown vote: missing validator id.")};
    }
    if (vote.round < 0) {
        return util::Error{Untranslated("Malformed Crown vote: negative round.")};
    }
    auto pubkey = DecodeKnownValidatorKey(validators, vote.validator_id);
    if (!pubkey) return util::Error{util::ErrorString(pubkey)};
    if (vote.signature.empty() || !pubkey->Verify(VoteSigningHash(vote), vote.signature)) {
        return util::Error{Untranslated(strprintf("Invalid Crown %s signature from '%s'.", VoteTypeName(vote.type), vote.validator_id))};
    }
    return {};
}

} // namespace crown::consensus
