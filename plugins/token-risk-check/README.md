# token-risk-check

Read-only T0 risk scoring for bounded, provider-verified token signals. It never accepts keys,
constructs transactions, signs, transfers, or trades. The current component exposes the pure
scoring core through the ZeroClaw tool boundary; live RPC/DAS adapters are added only after
fixture coverage is complete.
