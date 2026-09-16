// Copyright (c) 2026-present The Crown developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CROWN_CONSENSUS_TYPES_H
#define BITCOIN_CROWN_CONSENSUS_TYPES_H

#include <crown/validator.h>
#include <key.h>
#include <uint256.h>
#include <util/result.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace crown::consensus {

using BlockID = uint256;

inline constexpr int NO_VALID_ROUND{-1};

enum class Step : uint8_t {
    PROPOSE = 0,
    PREVOTE,
    PRECOMMIT,
    COMMIT,
};

enum class VoteType : uint8_t {
    PREVOTE = 0,
    PRECOMMIT,
};

enum class TimeoutKind : uint8_t {
    PROPOSE = 0,
    PREVOTE,
    PRECOMMIT,
};

struct Proposal {
    int64_t height{0};
    int round{0};
    std::string proposer_id;
    std::optional<BlockID> block_id;
    int valid_round{NO_VALID_ROUND};
    std::vector<unsigned char> signature;
};

struct Vote {
    VoteType type{VoteType::PREVOTE};
    int64_t height{0};
    int round{0};
    std::string validator_id;
    std::optional<BlockID> block_id;
    std::vector<unsigned char> signature;
};

struct EquivocationEvidence {
    Vote first_vote;
    Vote conflicting_vote;
};

struct CommitDecision {
    int64_t height{0};
    int round{0};
    BlockID block_id;
    std::vector<Vote> supporting_votes;
};

std::string_view StepName(Step step);
std::string_view VoteTypeName(VoteType type);
std::string_view TimeoutName(TimeoutKind timeout);

bool SameProposalPayload(const Proposal& lhs, const Proposal& rhs);
bool SameVotePayload(const Vote& lhs, const Vote& rhs);
bool VotesConflict(const Vote& lhs, const Vote& rhs);

uint256 ProposalSigningHash(const Proposal& proposal);
uint256 VoteSigningHash(const Vote& vote);

util::Result<void> SignProposal(Proposal& proposal, const CKey& private_key);
util::Result<void> SignVote(Vote& vote, const CKey& private_key);

util::Result<void> VerifyProposalSignature(const Proposal& proposal, std::span<const StaticValidator> validators);
util::Result<void> VerifyVoteSignature(const Vote& vote, std::span<const StaticValidator> validators);

} // namespace crown::consensus

#endif // BITCOIN_CROWN_CONSENSUS_TYPES_H
