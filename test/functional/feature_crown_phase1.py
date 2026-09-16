#!/usr/bin/env python3
# Copyright (c) 2026-present The Crown developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Basic startup coverage for the Crown successor Phase 1 scaffold."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

VALIDATOR_A_KEY = "0000000000000000000000000000000000000000000000000000000000000001"
VALIDATOR_B_KEY = "0000000000000000000000000000000000000000000000000000000000000002"


class CrownPhase1Test(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.chain = "crown"
        self.uses_wallet = False

    def run_test(self):
        node = self.nodes[0]

        info = node.getblockchaininfo()
        assert_equal(info["chain"], "crown")
        assert_equal(node.chain_path.name, "crown")

        self.generate(node, 1)
        self.stop_node(0)

        node.assert_start_raises_init_error(
            extra_args=["-crownvalidator=1"],
            expected_msg="Error: Crown validator mode requires both -crownvalidatorid and -crownvalidatorprivkey.",
        )
        node.assert_start_raises_init_error(
            extra_args=["-crownvalidatorid=validator-a"],
            expected_msg="Error: Crown validator identity and key options require -crownvalidator=1.",
        )
        node.assert_start_raises_init_error(
            extra_args=[
                "-crownvalidator=1",
                "-crownvalidatorid=validator-a",
                f"-crownvalidatorprivkey={VALIDATOR_B_KEY}",
            ],
            expected_msg="Error: Configured Crown validator private key does not match validator-a.",
        )

        self.start_node(0, extra_args=[
            "-crownvalidator=1",
            "-crownvalidatorid=validator-a",
            f"-crownvalidatorprivkey={VALIDATOR_A_KEY}",
        ])
        self.stop_node(0)


if __name__ == "__main__":
    CrownPhase1Test(__file__).main()
