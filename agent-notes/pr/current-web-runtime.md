# Goal
Upgrade web runtime to Node 24, Next.js 16 and React 19.

# State
Scoped contribution split from integrated revision e027f89, based independently on upstream main c66b9a0. Original implementation and runtime remain on fix-local-run-readiness. This branch contains only this concern plus this task note.

# Decisions and why
Use Node 24, Next.js 16 and React 19; migrate cookie access, route handlers and middleware to the current APIs. Update the graph renderer API, lint configuration, production dependency pins and lockfile, and disable Next telemetry in the image. Keep production TypeScript checking enabled.
Keep the PR independent of the other modernization branches; do not include local recovery history, credentials or deployment overrides.

# Surprises
These checks used the combined implementation; this isolated branch has not been built or run separately. Development dependency advisories and ESLint plugin peer-range warnings remain. No claim is made that the entire dependency tree is advisory-free. No local CI suite or browser/assistive-technology acceptance was run.

# Evidence
The integrated production UI image built successfully, including TypeScript checking. HTTP checks covered authentication, account/model access, dynamic missing-resource responses and logout. A production dependency advisory lookup for the final resolved graph returned no advisories.
Validation belongs to the integrated checkout, not this independently based branch. The six source scopes together reproduce its implementation, ignoring trailing whitespace.

# Next step
Upstream consideration and independent branch validation. No merge is authorized.
