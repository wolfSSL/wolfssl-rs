# Copyright wolfSSL Inc.
# SPDX-License-Identifier: MIT

include ../Makefile

test:
	cargo test --all-targets
	cargo test --release --all-targets

clippy-fix:
	cargo +nightly clippy --all-targets --fix --allow-dirty -- -W clippy::all  -W clippy::pedantic

ci: format clippy test api-diff-main

.PHONY: test ci clippy-fix
