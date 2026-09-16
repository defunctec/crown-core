// Copyright (c) 2026-present The Crown developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crown/consensus/engine.h>

#include <crown/consensus/types.h>
#include <crown/validator.h>
#include <tinyformat.h>
#include <util/result.h>
#include <util/translation.h>

#include <algorithm>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace crown::consensus {
namespace {

bool ContainsBlock(const std::vector<std::optional<BlockID>>& values, const std::optional<BlockID>& block_id)
{
    return std::ranges::find(values, block_id) != values.end();
}

const StaticValidator* FindValidatorById(const std::vector<StaticValidator>& validators, const std::string_view id)
{
    for (const auto& validator : validators) {
        if (validator.id == id) return &validator;
    }
    return nullptr;
}

} // namespace

Action Action::BroadcastVoteAction(Vote vote)
{
    Action action{Type::BROADCAST_VOTE};
    action.vote = std::move(vote);
    return action;
}

Action Action::CommitAction(CommitDecision commit)
{
    Action action{Type::COMMIT_DECISION};
    action.commit = std::move(commit);
    return action;
}

Action Action::EquivocationAction(EquivocationEvidence evidence)
{
    Action action{Type::EQUIVOCATION_EVIDENCE};
    action.evidence = std::move(evidence);
    return action;
}

ConsensusEngine::ConsensusEngine(EngineConfig config) :
    m_validators(config.validator_set.begin(), config.validator_set.end()),
    m_local_signer(std::move(config.local_signer)),
    m_total_voting_power(TotalVotingPower(config.validator_set))
{
}

std::vector<Action> ConsensusEngine::StartHeight(const int64_t height)
{
    m_state = ConsensusState{
        .height = height,
        .round = 0,
        .step = Step::PROPOSE,
    };
    m_round_votes.clear();
    m_local_signed_votes.clear();
    m_equivocations.clear();
    m_emitted_equivocations.clear();
    return {};
}

std::vector<Action> ConsensusEngine::EnterRound(const int round)
{
    m_state.round = round;
    m_state.step = Step::PROPOSE;
    m_state.current_proposal.reset();
    m_state.current_proposal_is_valid = false;
    return TryAdvance();
}

ConsensusEngine::RoundVotes& ConsensusEngine::MutableRoundVotes(const int round)
{
    return m_round_votes[round];
}

const ConsensusEngine::RoundVotes* ConsensusEngine::FindRoundVotes(const int round) const
{
    const auto it = m_round_votes.find(round);
    return it == m_round_votes.end() ? nullptr : &it->second;
}

std::string_view ConsensusEngine::ProposerForRound(const int round) const
{
    return m_validators[round % m_validators.size()].id;
}

bool ConsensusEngine::HasSeenPrevoteProof(const int round, const BlockID& block_id) const
{
    const RoundVotes* round_votes = FindRoundVotes(round);
    if (!round_votes) return false;
    return FindQuorum(round_votes->prevotes).has_quorum && FindQuorum(round_votes->prevotes).block_id == block_id;
}

bool ConsensusEngine::IsCurrentProposalUsable() const
{
    return m_state.current_proposal.has_value() &&
           m_state.current_proposal_is_valid &&
           m_state.current_proposal->block_id.has_value();
}

bool ConsensusEngine::ProposalAllowsPrevote(const Proposal& proposal) const
{
    if (!proposal.block_id.has_value()) return false;
    if (!m_state.locked_block.has_value()) return true;
    if (m_state.locked_block == proposal.block_id) return true;
    if (proposal.valid_round == NO_VALID_ROUND) return false;
    if (proposal.valid_round < m_state.locked_round) return false;
    return HasSeenPrevoteProof(proposal.valid_round, *proposal.block_id);
}

util::Result<Proposal> ConsensusEngine::MakeProposal(const BlockID block_id, const int valid_round) const
{
    if (!IsLocalValidator()) {
        return util::Error{Untranslated("This Crown consensus engine has no local validator signer.")};
    }
    if (m_state.commit.has_value()) {
        return util::Error{Untranslated("Cannot create a Crown proposal after commit.")};
    }
    if (m_state.height == 0) {
        return util::Error{Untranslated("Consensus height has not been started.")};
    }
    if (m_local_signer->validator_id != ProposerForRound(m_state.round)) {
        return util::Error{Untranslated(strprintf("Validator '%s' is not the proposer for round %d.", m_local_signer->validator_id, m_state.round))};
    }
    if (valid_round < NO_VALID_ROUND || valid_round >= m_state.round) {
        return util::Error{Untranslated("Crown proposal valid_round must be -1 or an earlier round.")};
    }

    Proposal proposal{
        .height = m_state.height,
        .round = m_state.round,
        .proposer_id = m_local_signer->validator_id,
        .block_id = block_id,
        .valid_round = valid_round,
    };
    if (auto signed_result = SignProposal(proposal, m_local_signer->private_key); !signed_result) {
        return util::Error{util::ErrorString(signed_result)};
    }
    return proposal;
}

util::Result<Vote> ConsensusEngine::MakeLocalVote(const VoteType type, const std::optional<BlockID> block_id)
{
    return BuildLocalVote(type, block_id);
}

bool ConsensusEngine::RegisterVote(const Vote& vote, std::vector<Action>& actions)
{
    auto& round_votes = MutableRoundVotes(vote.round);
    auto& vote_map = vote.type == VoteType::PREVOTE ? round_votes.prevotes : round_votes.precommits;
    const auto it = vote_map.find(vote.validator_id);
    if (it == vote_map.end()) {
        vote_map.emplace(vote.validator_id, vote);
        return true;
    }
    if (SameVotePayload(it->second, vote)) return false;

    if (VotesConflict(it->second, vote)) {
        const auto evidence_key = std::make_tuple(vote.validator_id, vote.type, vote.round);
        if (!m_emitted_equivocations.contains(evidence_key)) {
            EquivocationEvidence evidence{it->second, vote};
            m_equivocations.push_back(evidence);
            actions.push_back(Action::EquivocationAction(evidence));
            m_emitted_equivocations.emplace(evidence_key, true);
        }
    }
    return false;
}

ConsensusEngine::QuorumResult ConsensusEngine::FindQuorum(const std::map<std::string, Vote>& votes) const
{
    std::vector<std::optional<BlockID>> candidates;
    candidates.emplace_back(std::nullopt);
    for (const auto& [validator_id, vote] : votes) {
        (void)validator_id;
        if (!ContainsBlock(candidates, vote.block_id)) candidates.push_back(vote.block_id);
    }

    for (const auto& candidate : candidates) {
        int64_t voting_power{0};
        for (const auto& [validator_id, vote] : votes) {
            if (vote.block_id != candidate) continue;
            const StaticValidator* validator = FindValidatorById(m_validators, validator_id);
            if (!validator) continue;
            voting_power += validator->voting_power;
        }
        if (HasQuorum(voting_power, m_total_voting_power)) {
            return QuorumResult{
                .has_quorum = true,
                .block_id = candidate,
                .voting_power = voting_power,
            };
        }
    }

    return {};
}

std::vector<Vote> ConsensusEngine::CollectSupportingVotes(const std::map<std::string, Vote>& votes, const std::optional<BlockID>& block_id) const
{
    std::vector<Vote> supporting_votes;
    for (const auto& [validator_id, vote] : votes) {
        (void)validator_id;
        if (vote.block_id == block_id) supporting_votes.push_back(vote);
    }
    return supporting_votes;
}

void ConsensusEngine::UpdateValidBlock(const int round, const QuorumResult& prevote_quorum)
{
    if (!prevote_quorum.has_quorum || !prevote_quorum.block_id.has_value()) return;
    if (round < m_state.valid_round) return;

    m_state.valid_block = prevote_quorum.block_id;
    m_state.valid_round = round;
}

void ConsensusEngine::TryCommitRound(const int round, const RoundVotes& round_votes, std::vector<Action>& actions)
{
    if (m_state.commit.has_value()) return;

    const auto precommit_quorum = FindQuorum(round_votes.precommits);
    if (!precommit_quorum.has_quorum || !precommit_quorum.block_id.has_value()) return;

    m_state.step = Step::COMMIT;
    m_state.commit = CommitDecision{
        .height = m_state.height,
        .round = round,
        .block_id = *precommit_quorum.block_id,
        .supporting_votes = CollectSupportingVotes(round_votes.precommits, precommit_quorum.block_id),
    };
    actions.push_back(Action::CommitAction(*m_state.commit));
}

void ConsensusEngine::ObserveKnownRoundQuorums(std::vector<Action>& actions)
{
    for (const auto& [round, round_votes] : m_round_votes) {
        if (round > m_state.round) continue;
        UpdateValidBlock(round, FindQuorum(round_votes.prevotes));
        TryCommitRound(round, round_votes, actions);
        if (m_state.commit.has_value()) return;
    }
}

util::Result<Vote> ConsensusEngine::BuildLocalVote(const VoteType type, const std::optional<BlockID> block_id)
{
    if (!IsLocalValidator()) {
        return util::Error{Untranslated("This Crown consensus engine has no local validator signer.")};
    }

    const auto key = std::make_pair(type, m_state.round);
    const auto existing = m_local_signed_votes.find(key);
    if (existing != m_local_signed_votes.end()) {
        if (existing->second.block_id == block_id) {
            return util::Error{Untranslated(strprintf("Local validator already signed %s at height %d round %d.", VoteTypeName(type), m_state.height, m_state.round))};
        }
        return util::Error{Untranslated(strprintf("Local double-sign guard rejected conflicting %s at height %d round %d.", VoteTypeName(type), m_state.height, m_state.round))};
    }

    Vote vote{
        .type = type,
        .height = m_state.height,
        .round = m_state.round,
        .validator_id = m_local_signer->validator_id,
        .block_id = block_id,
    };
    if (auto signed_result = SignVote(vote, m_local_signer->private_key); !signed_result) {
        return util::Error{util::ErrorString(signed_result)};
    }
    m_local_signed_votes.emplace(key, vote);
    return vote;
}

std::vector<Action> ConsensusEngine::TryAdvance()
{
    std::vector<Action> actions;
    if (m_state.commit.has_value()) return actions;

    auto* current_round_votes = &MutableRoundVotes(m_state.round);
    if (current_round_votes->proposal.has_value()) {
        m_state.current_proposal = current_round_votes->proposal;
        m_state.current_proposal_is_valid = current_round_votes->proposal_is_valid;
    }

    if (IsLocalValidator() && m_state.step == Step::PROPOSE && IsCurrentProposalUsable()) {
        const auto prevote_block = ProposalAllowsPrevote(*m_state.current_proposal) ? m_state.current_proposal->block_id : std::nullopt;
        if (auto vote = BuildLocalVote(VoteType::PREVOTE, prevote_block); vote) {
            RegisterVote(*vote, actions);
            actions.push_back(Action::BroadcastVoteAction(*vote));
            m_state.step = Step::PREVOTE;
        }
    }

    const auto prevote_quorum = FindQuorum(current_round_votes->prevotes);
    if (prevote_quorum.has_quorum) {
        if (prevote_quorum.block_id.has_value() && IsCurrentProposalUsable() && m_state.current_proposal->block_id == prevote_quorum.block_id) {
            UpdateValidBlock(m_state.round, prevote_quorum);
            if (IsLocalValidator() && m_state.step != Step::COMMIT) {
                if (auto vote = BuildLocalVote(VoteType::PRECOMMIT, prevote_quorum.block_id); vote) {
                    RegisterVote(*vote, actions);
                    actions.push_back(Action::BroadcastVoteAction(*vote));
                    m_state.locked_block = prevote_quorum.block_id;
                    m_state.locked_round = m_state.round;
                    m_state.step = Step::PRECOMMIT;
                }
            }
        } else if (!prevote_quorum.block_id.has_value() && IsLocalValidator() && m_state.step != Step::COMMIT) {
            if (auto vote = BuildLocalVote(VoteType::PRECOMMIT, std::nullopt); vote) {
                RegisterVote(*vote, actions);
                actions.push_back(Action::BroadcastVoteAction(*vote));
                m_state.step = Step::PRECOMMIT;
            }
        }
    }

    ObserveKnownRoundQuorums(actions);

    return actions;
}

std::vector<Action> ConsensusEngine::ReceiveProposal(const Proposal& proposal, const bool block_valid)
{
    std::vector<Action> actions;
    if (m_state.commit.has_value()) return actions;

    if (auto verification = VerifyProposalSignature(proposal, m_validators); !verification) return actions;
    if (proposal.height != m_state.height || proposal.round != m_state.round) return actions;
    if (proposal.proposer_id != ProposerForRound(proposal.round)) return actions;
    if (proposal.valid_round != NO_VALID_ROUND && proposal.valid_round >= proposal.round) return actions;

    auto& round_votes = MutableRoundVotes(proposal.round);
    if (round_votes.proposal.has_value() && !SameProposalPayload(*round_votes.proposal, proposal)) return actions;

    round_votes.proposal = proposal;
    round_votes.proposal_is_valid = block_valid;
    m_state.current_proposal = proposal;
    m_state.current_proposal_is_valid = block_valid;
    auto next_actions = TryAdvance();
    actions.insert(actions.end(), next_actions.begin(), next_actions.end());
    return actions;
}

std::vector<Action> ConsensusEngine::ReceiveVote(const Vote& vote)
{
    std::vector<Action> actions;
    if (m_state.commit.has_value()) return actions;

    if (auto verification = VerifyVoteSignature(vote, m_validators); !verification) return actions;
    if (vote.height != m_state.height) return actions;

    RegisterVote(vote, actions);
    auto next_actions = vote.round == m_state.round ? TryAdvance() : std::vector<Action>{};
    if (vote.round != m_state.round) ObserveKnownRoundQuorums(actions);
    actions.insert(actions.end(), next_actions.begin(), next_actions.end());
    return actions;
}

std::vector<Action> ConsensusEngine::OnTimeout(const TimeoutKind timeout)
{
    std::vector<Action> actions;
    if (m_state.commit.has_value()) return actions;

    switch (timeout) {
    case TimeoutKind::PROPOSE:
        if (IsLocalValidator() && m_state.step == Step::PROPOSE) {
            if (auto vote = BuildLocalVote(VoteType::PREVOTE, std::nullopt); vote) {
                RegisterVote(*vote, actions);
                actions.push_back(Action::BroadcastVoteAction(*vote));
                m_state.step = Step::PREVOTE;
            }
        }
        break;
    case TimeoutKind::PREVOTE:
        if (IsLocalValidator() && m_state.step == Step::PREVOTE) {
            if (auto vote = BuildLocalVote(VoteType::PRECOMMIT, std::nullopt); vote) {
                RegisterVote(*vote, actions);
                actions.push_back(Action::BroadcastVoteAction(*vote));
                m_state.step = Step::PRECOMMIT;
            }
        }
        break;
    case TimeoutKind::PRECOMMIT:
        if (m_state.step == Step::PRECOMMIT) {
            return EnterRound(m_state.round + 1);
        }
        break;
    }

    auto next_actions = TryAdvance();
    actions.insert(actions.end(), next_actions.begin(), next_actions.end());
    return actions;
}

} // namespace crown::consensus
