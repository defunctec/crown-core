// Copyright (c) 2026-present The Crown developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crown/consensus/engine.h>
#include <crown/consensus/types.h>
#include <crown/validator.h>
#include <hash.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <deque>
#include <initializer_list>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(crown_consensus_tests, BasicTestingSetup)

namespace {

using crown::StaticValidator;
using crown::consensus::Action;
using crown::consensus::BlockID;
using crown::consensus::CommitDecision;
using crown::consensus::ConsensusEngine;
using crown::consensus::EngineConfig;
using crown::consensus::EquivocationEvidence;
using crown::consensus::LocalSigner;
using crown::consensus::NO_VALID_ROUND;
using crown::consensus::Proposal;
using crown::consensus::Step;
using crown::consensus::TimeoutKind;
using crown::consensus::Vote;
using crown::consensus::VoteType;

constexpr int64_t TEST_HEIGHT{101};

const std::array<std::string, 4> VALIDATOR_IDS{
    "validator-a",
    "validator-b",
    "validator-c",
    "validator-d",
};

BlockID TestBlock(std::string_view name)
{
    return (HashWriter{} << std::string{name}).GetHash();
}

LocalSigner GetSigner(std::string_view id)
{
    const auto* test_key = crown::FindTestValidatorPrivateKey(id);
    BOOST_REQUIRE_MESSAGE(test_key != nullptr, strprintf("missing test key for %s", id));
    auto private_key = crown::DecodeValidatorPrivateKey(test_key->private_key_hex);
    BOOST_REQUIRE(private_key);
    return LocalSigner{
        .validator_id = std::string{id},
        .private_key = *private_key,
    };
}

ConsensusEngine MakeEngine(std::string_view id)
{
    return ConsensusEngine(EngineConfig{
        .validator_set = crown::GetStaticValidatorSet(),
        .local_signer = GetSigner(id),
    });
}

Proposal MakeSignedProposal(std::string_view proposer_id, int64_t height, int round, BlockID block_id, int valid_round = NO_VALID_ROUND)
{
    Proposal proposal{
        .height = height,
        .round = round,
        .proposer_id = std::string{proposer_id},
        .block_id = block_id,
        .valid_round = valid_round,
    };
    auto signed_result = crown::consensus::SignProposal(proposal, GetSigner(proposer_id).private_key);
    BOOST_REQUIRE(signed_result);
    return proposal;
}

Vote MakeSignedVote(std::string_view validator_id, VoteType type, int64_t height, int round, std::optional<BlockID> block_id)
{
    Vote vote{
        .type = type,
        .height = height,
        .round = round,
        .validator_id = std::string{validator_id},
        .block_id = block_id,
    };
    auto signed_result = crown::consensus::SignVote(vote, GetSigner(validator_id).private_key);
    BOOST_REQUIRE(signed_result);
    return vote;
}

std::vector<Vote> VoteActions(const std::vector<Action>& actions)
{
    std::vector<Vote> votes;
    for (const auto& action : actions) {
        if (action.type == Action::Type::BROADCAST_VOTE) {
            BOOST_REQUIRE(action.vote.has_value());
            votes.push_back(*action.vote);
        }
    }
    return votes;
}

std::vector<CommitDecision> CommitActions(const std::vector<Action>& actions)
{
    std::vector<CommitDecision> commits;
    for (const auto& action : actions) {
        if (action.type == Action::Type::COMMIT_DECISION) {
            BOOST_REQUIRE(action.commit.has_value());
            commits.push_back(*action.commit);
        }
    }
    return commits;
}

std::vector<EquivocationEvidence> EvidenceActions(const std::vector<Action>& actions)
{
    std::vector<EquivocationEvidence> evidence;
    for (const auto& action : actions) {
        if (action.type == Action::Type::EQUIVOCATION_EVIDENCE) {
            BOOST_REQUIRE(action.evidence.has_value());
            evidence.push_back(*action.evidence);
        }
    }
    return evidence;
}

class DeterministicSimulator
{
public:
    DeterministicSimulator()
    {
        for (const auto& id : VALIDATOR_IDS) {
            m_nodes.emplace(id, std::make_unique<ConsensusEngine>(EngineConfig{
                .validator_set = crown::GetStaticValidatorSet(),
                .local_signer = GetSigner(id),
            }));
        }
        ResetLinks();
        for (const auto& id : VALIDATOR_IDS) {
            m_nodes.at(id)->StartHeight(TEST_HEIGHT);
        }
    }

    void ResetLinks()
    {
        for (const auto& sender : VALIDATOR_IDS) {
            auto& recipients = m_links[sender];
            recipients.clear();
            for (const auto& receiver : VALIDATOR_IDS) {
                if (receiver != sender) recipients.push_back(receiver);
            }
        }
    }

    void ClearLinks()
    {
        for (const auto& id : VALIDATOR_IDS) m_links[id].clear();
    }

    void ConnectClique(std::initializer_list<std::string_view> ids)
    {
        const std::vector<std::string> clique(ids.begin(), ids.end());
        for (const auto& sender : clique) {
            auto& recipients = m_links[sender];
            recipients.clear();
            for (const auto& receiver : clique) {
                if (receiver != sender) recipients.push_back(receiver);
            }
        }
    }

    void SetRecipients(std::string_view sender, std::initializer_list<std::string_view> recipients)
    {
        auto& list = m_links[std::string{sender}];
        list.clear();
        for (const auto& recipient : recipients) list.push_back(std::string{recipient});
    }

    Proposal MakeProposal(std::string_view proposer_id, BlockID block_id, int valid_round = NO_VALID_ROUND)
    {
        auto proposal = m_nodes.at(std::string{proposer_id})->MakeProposal(block_id, valid_round);
        BOOST_REQUIRE(proposal);
        return *proposal;
    }

    void DeliverProposal(const Proposal& proposal, bool block_valid, std::initializer_list<std::string_view> recipients)
    {
        for (const auto& recipient : recipients) {
            auto actions = m_nodes.at(std::string{recipient})->ReceiveProposal(proposal, block_valid);
            EnqueueActions(recipient, actions);
            CheckSafetyInvariant();
        }
    }

    void DeliverVote(const Vote& vote, std::initializer_list<std::string_view> recipients)
    {
        for (const auto& recipient : recipients) {
            auto actions = m_nodes.at(std::string{recipient})->ReceiveVote(vote);
            EnqueueActions(recipient, actions);
            CheckSafetyInvariant();
        }
    }

    void Timeout(TimeoutKind timeout, std::initializer_list<std::string_view> recipients)
    {
        for (const auto& recipient : recipients) {
            auto actions = m_nodes.at(std::string{recipient})->OnTimeout(timeout);
            EnqueueActions(recipient, actions);
            CheckSafetyInvariant();
        }
    }

    void DeliverNextQueuedVote(std::size_t index = 0)
    {
        BOOST_REQUIRE(index < m_queue.size());
        const QueuedVote queued = m_queue.at(index);
        m_queue.erase(m_queue.begin() + index);
        for (const auto& recipient : queued.recipients) {
            auto actions = m_nodes.at(recipient)->ReceiveVote(queued.vote);
            EnqueueActions(recipient, actions);
            CheckSafetyInvariant();
        }
    }

    void DeliverAllQueuedVotes()
    {
        while (!m_queue.empty()) DeliverNextQueuedVote(0);
    }

    std::size_t PendingVotes() const
    {
        return m_queue.size();
    }

    std::vector<Vote> QueuedVotes() const
    {
        std::vector<Vote> votes;
        for (const auto& queued : m_queue) votes.push_back(queued.vote);
        return votes;
    }

    const ConsensusEngine& Node(std::string_view id) const
    {
        return *m_nodes.at(std::string{id});
    }

private:
    struct QueuedVote {
        Vote vote;
        std::vector<std::string> recipients;
    };

    std::map<std::string, std::unique_ptr<ConsensusEngine>> m_nodes;
    std::map<std::string, std::vector<std::string>> m_links;
    std::deque<QueuedVote> m_queue;

    void EnqueueActions(std::string_view origin, const std::vector<Action>& actions)
    {
        for (const auto& action : actions) {
            if (action.type != Action::Type::BROADCAST_VOTE) continue;
            BOOST_REQUIRE(action.vote.has_value());
            m_queue.push_back(QueuedVote{
                .vote = *action.vote,
                .recipients = m_links.at(std::string{origin}),
            });
        }
    }

    void CheckSafetyInvariant() const
    {
        std::optional<BlockID> committed_block;
        for (const auto& [id, node] : m_nodes) {
            (void)id;
            const auto& commit = node->GetState().commit;
            if (!commit.has_value()) continue;
            if (!committed_block.has_value()) {
                committed_block = commit->block_id;
                continue;
            }
            BOOST_REQUIRE_MESSAGE(*committed_block == commit->block_id, "conflicting block commits observed at the same height");
        }
    }
};

void AssertCommitted(const ConsensusEngine& engine, BlockID block_id, int round)
{
    BOOST_REQUIRE(engine.GetState().commit.has_value());
    BOOST_CHECK(engine.GetState().step == Step::COMMIT);
    BOOST_CHECK_EQUAL(engine.GetState().commit->height, TEST_HEIGHT);
    BOOST_CHECK_EQUAL(engine.GetState().commit->round, round);
    BOOST_CHECK(engine.GetState().commit->block_id == block_id);
}

void AssertNotCommitted(const ConsensusEngine& engine)
{
    BOOST_CHECK(!engine.GetState().commit.has_value());
}

} // namespace

BOOST_AUTO_TEST_CASE(crown_consensus_honest_four_of_four_commit)
{
    DeterministicSimulator sim;
    const BlockID x = TestBlock("X");

    const Proposal proposal = sim.MakeProposal("validator-a", x);
    sim.DeliverProposal(proposal, /*block_valid=*/true, {"validator-a", "validator-b", "validator-c", "validator-d"});
    sim.DeliverAllQueuedVotes();

    for (const auto& id : VALIDATOR_IDS) AssertCommitted(sim.Node(id), x, 0);
}

BOOST_AUTO_TEST_CASE(crown_consensus_availability_thresholds)
{
    const BlockID x = TestBlock("availability");

    {
        DeterministicSimulator sim;
        sim.ClearLinks();
        sim.ConnectClique({"validator-a", "validator-b", "validator-c"});

        const Proposal proposal = sim.MakeProposal("validator-a", x);
        sim.DeliverProposal(proposal, true, {"validator-a", "validator-b", "validator-c"});
        sim.DeliverAllQueuedVotes();

        AssertCommitted(sim.Node("validator-a"), x, 0);
        AssertCommitted(sim.Node("validator-b"), x, 0);
        AssertCommitted(sim.Node("validator-c"), x, 0);
        AssertNotCommitted(sim.Node("validator-d"));
    }

    {
        DeterministicSimulator sim;
        sim.ClearLinks();
        sim.ConnectClique({"validator-a", "validator-b"});

        const Proposal proposal = sim.MakeProposal("validator-a", x);
        sim.DeliverProposal(proposal, true, {"validator-a", "validator-b"});
        sim.DeliverAllQueuedVotes();

        AssertNotCommitted(sim.Node("validator-a"));
        AssertNotCommitted(sim.Node("validator-b"));
        AssertNotCommitted(sim.Node("validator-c"));
        AssertNotCommitted(sim.Node("validator-d"));
    }
}

BOOST_AUTO_TEST_CASE(crown_consensus_proposer_timeout_invalid_proposal_and_nil_round_progress)
{
    const BlockID x = TestBlock("round-progress");

    {
        DeterministicSimulator sim;
        sim.ClearLinks();
        sim.ConnectClique({"validator-b", "validator-c", "validator-d"});

        sim.Timeout(TimeoutKind::PROPOSE, {"validator-b", "validator-c", "validator-d"});
        sim.DeliverAllQueuedVotes();
        sim.Timeout(TimeoutKind::PRECOMMIT, {"validator-b", "validator-c", "validator-d"});

        BOOST_CHECK_EQUAL(sim.Node("validator-b").GetState().round, 1);
        BOOST_CHECK_EQUAL(sim.Node("validator-c").GetState().round, 1);
        BOOST_CHECK_EQUAL(sim.Node("validator-d").GetState().round, 1);

        const Proposal proposal = sim.MakeProposal("validator-b", x);
        sim.DeliverProposal(proposal, true, {"validator-b", "validator-c", "validator-d"});
        sim.DeliverAllQueuedVotes();

        AssertCommitted(sim.Node("validator-b"), x, 1);
        AssertCommitted(sim.Node("validator-c"), x, 1);
        AssertCommitted(sim.Node("validator-d"), x, 1);
        AssertNotCommitted(sim.Node("validator-a"));
    }

    {
        DeterministicSimulator sim;
        const Proposal invalid = sim.MakeProposal("validator-a", x);
        sim.DeliverProposal(invalid, /*block_valid=*/false, {"validator-a", "validator-b", "validator-c", "validator-d"});
        BOOST_CHECK_EQUAL(sim.PendingVotes(), 0U);

        sim.Timeout(TimeoutKind::PROPOSE, {"validator-a", "validator-b", "validator-c", "validator-d"});
        const auto nil_prevotes = sim.QueuedVotes();
        BOOST_REQUIRE(!nil_prevotes.empty());
        for (const auto& vote : nil_prevotes) {
            BOOST_CHECK(vote.type == VoteType::PREVOTE);
            BOOST_CHECK(!vote.block_id.has_value());
        }

        sim.DeliverAllQueuedVotes();
        AssertNotCommitted(sim.Node("validator-a"));
        AssertNotCommitted(sim.Node("validator-b"));
        AssertNotCommitted(sim.Node("validator-c"));
        AssertNotCommitted(sim.Node("validator-d"));

        sim.Timeout(TimeoutKind::PRECOMMIT, {"validator-a", "validator-b", "validator-c", "validator-d"});
        BOOST_CHECK_EQUAL(sim.Node("validator-a").GetState().round, 1);
    }
}

BOOST_AUTO_TEST_CASE(crown_consensus_vote_validation_duplicate_and_filtering)
{
    ConsensusEngine engine = MakeEngine("validator-a");
    const BlockID x = TestBlock("valid");
    const BlockID y = TestBlock("other");

    engine.StartHeight(TEST_HEIGHT);
    const Proposal proposal = MakeSignedProposal("validator-a", TEST_HEIGHT, 0, x);
    const auto on_proposal = engine.ReceiveProposal(proposal, true);
    BOOST_REQUIRE_EQUAL(VoteActions(on_proposal).size(), 1U);
    BOOST_CHECK(VoteActions(on_proposal).front().block_id == x);

    const Vote b_prevote_x = MakeSignedVote("validator-b", VoteType::PREVOTE, TEST_HEIGHT, 0, x);
    BOOST_CHECK(engine.ReceiveVote(b_prevote_x).empty());
    BOOST_CHECK(engine.ReceiveVote(b_prevote_x).empty());
    BOOST_CHECK(engine.GetState().step == Step::PREVOTE);

    Vote unknown_vote = b_prevote_x;
    unknown_vote.validator_id = "validator-z";
    BOOST_CHECK(engine.ReceiveVote(unknown_vote).empty());

    Vote invalid_signature = b_prevote_x;
    invalid_signature.signature.back() ^= 1;
    BOOST_CHECK(engine.ReceiveVote(invalid_signature).empty());

    const Vote wrong_height = MakeSignedVote("validator-c", VoteType::PREVOTE, TEST_HEIGHT + 1, 0, x);
    BOOST_CHECK(engine.ReceiveVote(wrong_height).empty());

    engine.OnTimeout(TimeoutKind::PROPOSE);
    engine.OnTimeout(TimeoutKind::PREVOTE);
    engine.OnTimeout(TimeoutKind::PRECOMMIT);
    BOOST_CHECK_EQUAL(engine.GetState().round, 1);

    const Vote stale_round = MakeSignedVote("validator-c", VoteType::PREVOTE, TEST_HEIGHT, 0, x);
    BOOST_CHECK(engine.ReceiveVote(stale_round).empty());
    BOOST_CHECK_EQUAL(engine.GetState().round, 1);
    BOOST_CHECK(engine.GetState().step == Step::PROPOSE);

    const Vote c_prevote_x = MakeSignedVote("validator-c", VoteType::PREVOTE, TEST_HEIGHT, 0, x);
    const auto after_c = engine.ReceiveVote(c_prevote_x);
    BOOST_CHECK(after_c.empty());

    const auto explicit_guard_vote = engine.MakeLocalVote(VoteType::PREVOTE, y);
    BOOST_CHECK(!explicit_guard_vote);
}

BOOST_AUTO_TEST_CASE(crown_consensus_prevote_nil_and_precommit_nil_do_not_commit)
{
    ConsensusEngine engine = MakeEngine("validator-a");
    engine.StartHeight(TEST_HEIGHT);

    const auto propose_timeout = engine.OnTimeout(TimeoutKind::PROPOSE);
    const auto prevotes = VoteActions(propose_timeout);
    BOOST_REQUIRE_EQUAL(prevotes.size(), 1U);
    BOOST_CHECK(prevotes.front().type == VoteType::PREVOTE);
    BOOST_CHECK(!prevotes.front().block_id.has_value());
    BOOST_CHECK(engine.GetState().step == Step::PREVOTE);

    const Vote b_nil = MakeSignedVote("validator-b", VoteType::PREVOTE, TEST_HEIGHT, 0, std::nullopt);
    const Vote c_nil = MakeSignedVote("validator-c", VoteType::PREVOTE, TEST_HEIGHT, 0, std::nullopt);
    const auto after_b = engine.ReceiveVote(b_nil);
    BOOST_CHECK(after_b.empty());
    const auto after_c = engine.ReceiveVote(c_nil);
    const auto precommits = VoteActions(after_c);
    BOOST_REQUIRE_EQUAL(precommits.size(), 1U);
    BOOST_CHECK(precommits.front().type == VoteType::PRECOMMIT);
    BOOST_CHECK(!precommits.front().block_id.has_value());
    AssertNotCommitted(engine);

    const Vote d_nil = MakeSignedVote("validator-d", VoteType::PRECOMMIT, TEST_HEIGHT, 0, std::nullopt);
    BOOST_CHECK(engine.ReceiveVote(d_nil).empty());
    AssertNotCommitted(engine);
}

BOOST_AUTO_TEST_CASE(crown_consensus_equivocation_detection_for_prevote_and_precommit)
{
    ConsensusEngine engine = MakeEngine("validator-a");
    const BlockID x = TestBlock("eq-x");
    const BlockID y = TestBlock("eq-y");

    engine.StartHeight(TEST_HEIGHT);
    const Proposal proposal = MakeSignedProposal("validator-a", TEST_HEIGHT, 0, x);
    engine.ReceiveProposal(proposal, true);

    const Vote b_prevote_x = MakeSignedVote("validator-b", VoteType::PREVOTE, TEST_HEIGHT, 0, x);
    const Vote b_prevote_y = MakeSignedVote("validator-b", VoteType::PREVOTE, TEST_HEIGHT, 0, y);
    BOOST_CHECK(engine.ReceiveVote(b_prevote_x).empty());
    const auto prevote_conflict = engine.ReceiveVote(b_prevote_y);
    const auto prevote_evidence = EvidenceActions(prevote_conflict);
    BOOST_REQUIRE_EQUAL(prevote_evidence.size(), 1U);
    BOOST_CHECK(prevote_evidence.front().first_vote.block_id == x);
    BOOST_CHECK(prevote_evidence.front().conflicting_vote.block_id == y);

    const Vote c_prevote_x = MakeSignedVote("validator-c", VoteType::PREVOTE, TEST_HEIGHT, 0, x);
    const auto after_c = engine.ReceiveVote(c_prevote_x);
    const auto precommit_actions = VoteActions(after_c);
    BOOST_REQUIRE_EQUAL(precommit_actions.size(), 1U);
    BOOST_CHECK(precommit_actions.front().type == VoteType::PRECOMMIT);
    BOOST_CHECK(precommit_actions.front().block_id == x);

    const Vote b_precommit_x = MakeSignedVote("validator-b", VoteType::PRECOMMIT, TEST_HEIGHT, 0, x);
    const Vote b_precommit_y = MakeSignedVote("validator-b", VoteType::PRECOMMIT, TEST_HEIGHT, 0, y);
    BOOST_CHECK(engine.ReceiveVote(b_precommit_x).empty());
    const auto precommit_conflict = engine.ReceiveVote(b_precommit_y);
    const auto precommit_evidence = EvidenceActions(precommit_conflict);
    BOOST_REQUIRE_EQUAL(precommit_evidence.size(), 1U);
    BOOST_CHECK(precommit_evidence.front().first_vote.block_id == x);
    BOOST_CHECK(precommit_evidence.front().conflicting_vote.block_id == y);
}

BOOST_AUTO_TEST_CASE(crown_consensus_lock_rule_rejects_conflicting_proposal_without_valid_round)
{
    ConsensusEngine engine = MakeEngine("validator-a");
    const BlockID x = TestBlock("lock-x");
    const BlockID y = TestBlock("lock-y");

    engine.StartHeight(TEST_HEIGHT);
    engine.ReceiveProposal(MakeSignedProposal("validator-a", TEST_HEIGHT, 0, x), true);
    engine.ReceiveVote(MakeSignedVote("validator-b", VoteType::PREVOTE, TEST_HEIGHT, 0, x));
    const auto lock_actions = engine.ReceiveVote(MakeSignedVote("validator-c", VoteType::PREVOTE, TEST_HEIGHT, 0, x));
    BOOST_REQUIRE_EQUAL(VoteActions(lock_actions).size(), 1U);
    BOOST_CHECK(engine.GetState().locked_block == x);
    BOOST_CHECK_EQUAL(engine.GetState().locked_round, 0);

    engine.OnTimeout(TimeoutKind::PRECOMMIT);
    BOOST_CHECK_EQUAL(engine.GetState().round, 1);

    const auto conflict_actions = engine.ReceiveProposal(MakeSignedProposal("validator-b", TEST_HEIGHT, 1, y), true);
    const auto votes = VoteActions(conflict_actions);
    BOOST_REQUIRE_EQUAL(votes.size(), 1U);
    BOOST_CHECK(votes.front().type == VoteType::PREVOTE);
    BOOST_CHECK(!votes.front().block_id.has_value());
    BOOST_CHECK(engine.GetState().locked_block == x);
}

BOOST_AUTO_TEST_CASE(crown_consensus_valid_round_allows_safe_lock_transition)
{
    ConsensusEngine engine = MakeEngine("validator-a");
    const BlockID x = TestBlock("valid-round-x");
    const BlockID y = TestBlock("valid-round-y");

    engine.StartHeight(TEST_HEIGHT);
    engine.ReceiveProposal(MakeSignedProposal("validator-a", TEST_HEIGHT, 0, x), true);
    engine.ReceiveVote(MakeSignedVote("validator-b", VoteType::PREVOTE, TEST_HEIGHT, 0, x));
    engine.ReceiveVote(MakeSignedVote("validator-c", VoteType::PREVOTE, TEST_HEIGHT, 0, x));
    BOOST_CHECK(engine.GetState().locked_block == x);
    BOOST_CHECK_EQUAL(engine.GetState().locked_round, 0);

    engine.OnTimeout(TimeoutKind::PRECOMMIT);
    engine.OnTimeout(TimeoutKind::PROPOSE);
    engine.OnTimeout(TimeoutKind::PREVOTE);
    engine.OnTimeout(TimeoutKind::PRECOMMIT);
    BOOST_CHECK_EQUAL(engine.GetState().round, 2);

    BOOST_CHECK(engine.ReceiveVote(MakeSignedVote("validator-b", VoteType::PREVOTE, TEST_HEIGHT, 1, y)).empty());
    BOOST_CHECK(engine.ReceiveVote(MakeSignedVote("validator-c", VoteType::PREVOTE, TEST_HEIGHT, 1, y)).empty());
    BOOST_CHECK(engine.ReceiveVote(MakeSignedVote("validator-d", VoteType::PREVOTE, TEST_HEIGHT, 1, y)).empty());
    BOOST_CHECK(engine.HasSeenPrevoteProof(1, y));

    const auto actions = engine.ReceiveProposal(MakeSignedProposal("validator-c", TEST_HEIGHT, 2, y, 1), true);
    const auto votes = VoteActions(actions);
    BOOST_REQUIRE_EQUAL(votes.size(), 1U);
    BOOST_CHECK(votes.front().type == VoteType::PREVOTE);
    BOOST_CHECK(votes.front().block_id == y);
}

BOOST_AUTO_TEST_CASE(crown_consensus_partition_behavior)
{
    const BlockID x = TestBlock("partition-3-1");

    {
        DeterministicSimulator sim;
        sim.ClearLinks();
        sim.ConnectClique({"validator-a", "validator-b", "validator-c"});
        sim.SetRecipients("validator-d", {});

        const Proposal proposal = sim.MakeProposal("validator-a", x);
        sim.DeliverProposal(proposal, true, {"validator-a", "validator-b", "validator-c"});
        sim.DeliverAllQueuedVotes();

        AssertCommitted(sim.Node("validator-a"), x, 0);
        AssertCommitted(sim.Node("validator-b"), x, 0);
        AssertCommitted(sim.Node("validator-c"), x, 0);
        AssertNotCommitted(sim.Node("validator-d"));
    }

    {
        DeterministicSimulator sim;
        sim.ClearLinks();
        sim.ConnectClique({"validator-a", "validator-b"});
        sim.ConnectClique({"validator-c", "validator-d"});

        const Proposal proposal = sim.MakeProposal("validator-a", x);
        sim.DeliverProposal(proposal, true, {"validator-a", "validator-b"});
        sim.DeliverAllQueuedVotes();

        AssertNotCommitted(sim.Node("validator-a"));
        AssertNotCommitted(sim.Node("validator-b"));
        AssertNotCommitted(sim.Node("validator-c"));
        AssertNotCommitted(sim.Node("validator-d"));
    }
}

BOOST_AUTO_TEST_CASE(crown_consensus_message_order_permutations_preserve_safety)
{
    const BlockID x = TestBlock("ordering");

    for (uint32_t seed = 1; seed <= 24; ++seed) {
        DeterministicSimulator sim;
        const Proposal proposal = sim.MakeProposal("validator-a", x);
        sim.DeliverProposal(proposal, true, {"validator-a", "validator-b", "validator-c", "validator-d"});

        uint32_t state = seed;
        while (sim.PendingVotes() > 0) {
            state = state * 1103515245U + 12345U;
            const std::size_t index = state % sim.PendingVotes();
            sim.DeliverNextQueuedVote(index);
        }

        for (const auto& id : VALIDATOR_IDS) AssertCommitted(sim.Node(id), x, 0);
    }
}

BOOST_AUTO_TEST_CASE(crown_consensus_commit_action_contains_supporting_votes)
{
    ConsensusEngine engine = MakeEngine("validator-a");
    const BlockID x = TestBlock("commit-support");

    engine.StartHeight(TEST_HEIGHT);
    engine.ReceiveProposal(MakeSignedProposal("validator-a", TEST_HEIGHT, 0, x), true);
    engine.ReceiveVote(MakeSignedVote("validator-b", VoteType::PREVOTE, TEST_HEIGHT, 0, x));
    engine.ReceiveVote(MakeSignedVote("validator-c", VoteType::PREVOTE, TEST_HEIGHT, 0, x));
    engine.ReceiveVote(MakeSignedVote("validator-b", VoteType::PRECOMMIT, TEST_HEIGHT, 0, x));
    const auto commit_actions = engine.ReceiveVote(MakeSignedVote("validator-c", VoteType::PRECOMMIT, TEST_HEIGHT, 0, x));
    const auto commits = CommitActions(commit_actions);
    BOOST_REQUIRE_EQUAL(commits.size(), 1U);
    BOOST_CHECK_EQUAL(commits.front().supporting_votes.size(), 3U);
    BOOST_CHECK(commits.front().block_id == x);
}

BOOST_AUTO_TEST_CASE(crown_consensus_local_double_sign_guard_blocks_conflicting_signatures)
{
    ConsensusEngine engine = MakeEngine("validator-a");
    const BlockID x = TestBlock("double-sign-x");
    const BlockID y = TestBlock("double-sign-y");

    engine.StartHeight(TEST_HEIGHT);
    auto first = engine.MakeLocalVote(VoteType::PREVOTE, x);
    BOOST_REQUIRE(first);
    auto second = engine.MakeLocalVote(VoteType::PREVOTE, y);
    BOOST_CHECK(!second);
}

BOOST_AUTO_TEST_SUITE_END()
