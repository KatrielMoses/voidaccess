# Goal
Make corpus sharing opt-in and disclose investigation data flow.

# State
Scoped contribution split from integrated revision e027f89, based independently on upstream main c66b9a0. Original implementation and runtime remain on fix-local-run-readiness. This branch contains only this concern plus this task note.

# Decisions and why
Make corpus sharing opt-in, explain the separate search, enrichment, hosted-model and local-storage data flows, and select a restricted enrichment list in the example environment. Remove the authorization-bypass setting and preambles while preserving content-safety checks. Move spaCy model installation out of the investigation command and update existing consent/prompt fixtures.
Keep the PR independent of the other modernization branches; do not include local recovery history, credentials or deployment overrides.

# Surprises
This isolated branch has not been built or run separately. Corpus private mode does not make investigations offline. The sample enrichment list only applies when configured; an unset or blank allowlist still enables all eligible sources. No personal investigation was performed.

# Evidence
The combined stack was built and used with private corpus defaults. Existing fixtures were adjusted for explicit sharing consent and the revised prompts; those test files were not run locally.
Validation belongs to the integrated checkout, not this independently based branch. The six source scopes together reproduce its implementation, ignoring trailing whitespace.

# Next step
Upstream consideration and independent branch validation. No merge is authorized.
