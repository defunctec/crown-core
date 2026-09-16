// Copyright (c) 2026-present The Crown developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CROWN_CONSENSUS_ENGINE_H
#define BITCOIN_CROWN_CONSENSUS_ENGINE_H

#include <crown/consensus/types.h>
#include <crown/validator.h>
#include <key.h>
#include <uint256.h>
#include <util/result.h>

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace crown::consensus {

struct LocalSigner {
    std::string validator_id;
    CKey private_key;
};

struct ConsensusState {
    int64_t height{0};
    int round{0};
    Step step{Step::PROPOSE};
    std::optional<BlockID> locked_block;
    int locked_round{NO_VALID_ROUND};
    std::optional<BlockID> valid_block;
    int valid_round{NO_VALID_ROUND};
    std::optional<Proposal> current_proposal;
    bool current_proposal_is_valid{false};
    std::optional<CommitDecision> commit;
};

struct Action {
    enum class Type : uint8_t {
        BROADCAST_VOTE = 0,
        COMMIT_DECISION,
        EQUIVOCATION_EVIDENCE,
    };

    Type type;
    std::optional<Vote> vote;
    std::optional<CommitDecision> commit;
    std::optional<EquivocationEvidence> evidence;

    static Action BroadcastVoteAction(Vote vote);
    static Action CommitAction(CommitDecision commit);
    static Action EquivocationAction(EquivocationEvidence evidence);
};

struct EngineConfig {
    std::span<const StaticValidator> validator_set;
    std::optional<LocalSigner> local_signer;
};

class ConsensusEngine
{
public:
    explicit ConsensusEngine(EngineConfig config);

    std::vector<Action> StartHeight(int64_t height);
    std::vector<Action> ReceiveProposal(const Proposal& proposal, bool block_valid);
    std::vector<Action> ReceiveVote(const Vote& vote);
    std::vector<Action> OnTimeout(TimeoutKind timeout);

    util::Result<Proposal> MakeProposal(BlockID block_id, int valid_round = NO_VALID_ROUND) const;
    util::Result<Vote> MakeLocalVote(VoteType type, std::optional<BlockID> block_id);

    const ConsensusState& GetState() const { return m_state; }
    std::string_view ProposerForRound(int round) const;
    bool HasSeenPrevoteProof(int round, const BlockID& block_id) const;
    const std::vector<EquivocationEvidence>& GetEquivocationEvidence() const { return m_equivocations; }

private:
    struct RoundVotes {
        std::optional<Proposal> proposal;
        bool proposal_is_valid{false};
        std::map<std::string, Vote> prevotes;
        std::map<std::string, Vote> precommits;
    };

    struct QuorumResult {
        bool has_quorum{false};
        std::optional<BlockID> block_id;
        int64_t voting_power{0};
    };

    std::vector<StaticValidator> m_validators;
    std::optional<LocalSigner> m_local_signer;
    int64_t m_total_voting_power{0};
    ConsensusState m_state;
    std::map<int, RoundVotes> m_round_votes;
    std::map<std::pair<VoteType, int>, Vote> m_local_signed_votes;
    std::vector<EquivocationEvidence> m_equivocations;
    std::map<std::tuple<std::string, VoteType, int>, bool> m_emitted_equivocations;

    RoundVotes& MutableRoundVotes(int round);
    const RoundVotes* FindRoundVotes(int round) const;

    bool IsLocalValidator() const { return m_local_signer.has_value(); }
    bool IsCurrentProposalUsable() const;
    bool ProposalAllowsPrevote(const Proposal& proposal) const;
    bool RegisterVote(const Vote& vote, std::vector<Action>& actions);
    QuorumResult FindQuorum(const std::map<std::string, Vote>& votes) const;
    void UpdateValidBlock(int round, const QuorumResult& prevote_quorum);
    void TryCommitRound(int round, const RoundVotes& round_votes, std::vector<Action>& actions);
    void ObserveKnownRoundQuorums(std::vector<Action>& actions);
    std::vector<Vote> CollectSupportingVotes(const std::map<std::string, Vote>& votes, const std::optional<BlockID>& block_id) const;
    util::Result<Vote> BuildLocalVote(VoteType type, std::optional<BlockID> block_id);
    std::vector<Action> TryAdvance();
    std::vector<Action> EnterRound(int round);
};

} // namespace crown::consensus

#endif // BITCOIN_CROWN_CONSENSUS_ENGINE_H
