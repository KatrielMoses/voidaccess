# Goal
Migrate Etherscan and report source coverage accurately.

# State
Scoped contribution split from integrated revision e027f89, based independently on upstream main c66b9a0. Original implementation and runtime remain on fix-local-run-readiness. This branch contains only this concern plus this task note.

# Decisions and why
Use Etherscan API V2 with the Ethereum mainnet chain ID and provider-error handling. Skip unsupported anonymous paste searches without making those requests, while retaining collection of discovered public URLs. Persist canonical tracked source outcomes and expose disabled, unconfigured, skipped, failed, partial and empty results in source rows; preserve explicit toggle outcomes.
Keep the PR independent of the other modernization branches; do not include local recovery history, credentials or deployment overrides.

# Surprises
This isolated branch has not been built or run separately. Authenticated Etherscan acceptance was not performed because no key was configured. A completed investigation can still have coverage gaps. Existing feed work in #20 is outside this PR; no feed URLs or feed parser are changed. No local CI suite was run.

# Evidence
Live probes confirmed the retired Etherscan V1 endpoint and unavailable anonymous paste searches. In the integrated runtime, a public-query paste invocation reported the umbrella and four child sources as skipped, with zero results and zero requests.
Validation belongs to the integrated checkout, not this independently based branch. The six source scopes together reproduce its implementation, ignoring trailing whitespace.

# Next step
Upstream consideration and independent branch validation. No merge is authorized.
