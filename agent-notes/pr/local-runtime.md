# Goal
Fix local Docker runtime, service defaults and token revocation.

# State
Scoped contribution split from integrated revision e027f89, based independently on upstream main c66b9a0. Original implementation and runtime remain on fix-local-run-readiness. This branch contains only this concern plus this task note.

# Decisions and why
Install the complete application and vector dependencies, retain the bundled seed snapshot, and cache dependency/model layers independently of source changes. Bind published services to localhost, generate the required Meilisearch secret during setup, and keep optional Chromium rendering disabled unless its sandbox is available. Normalize blank Redis configuration to use the existing database revocation backend and correct its authentication documentation.
Keep the PR independent of the other modernization branches; do not include local recovery history, credentials or deployment overrides.

# Surprises
These checks used the combined implementation before this split; this isolated branch has not been built or run separately. Optional Chromium rendering was not exercised. No local CI suite was run. This overlaps the Dockerfile portion of #19; it makes no migration changes.

# Evidence
The integrated implementation built both production images and started all five services. Manual HTTP checks passed readiness, login, account access, logout, and rejection of the revoked cookie. A warm backend build reused the dependency and model layers.
Validation belongs to the integrated checkout, not this independently based branch. The six source scopes together reproduce its implementation, ignoring trailing whitespace.

# Next step
Upstream consideration and independent branch validation. No merge is authorized.
