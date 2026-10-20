# Goal
Rank query-matching excerpts within the encoder context.

# State
Scoped contribution split from integrated revision e027f89, based independently on upstream main c66b9a0. Original implementation and runtime remain on fix-local-run-readiness. This branch contains only this concern plus this task note.

# Decisions and why
Request query-centred Meilisearch content excerpts for reranking and use the encoder's actual context limit instead of a hard-coded token length. Retain the existing embedding model, dimensions and index schema, and document the retrieval limit.
Keep the PR independent of the other modernization branches; do not include local recovery history, credentials or deployment overrides.

# Surprises
This isolated branch has not been run separately. The small comparison establishes no broad recall improvement, and excerpt reranking does not provide exhaustive semantic recall across every passage. No local CI suite was run.

# Evidence
On the integrated implementation, the real encoder reported fallback=false, 256-token context and 384 dimensions. A 14-public-page, six-query comparison retained MRR 0.8333 while passing later matching passages to the ranker.
Validation belongs to the integrated checkout, not this independently based branch. The six source scopes together reproduce its implementation, ignoring trailing whitespace.

# Next step
Upstream consideration and independent branch validation. No merge is authorized.
