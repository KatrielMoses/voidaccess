# Goal
Refresh LLM providers, credential routing and model selection.

# State
Scoped contribution split from integrated revision e027f89, based independently on upstream main c66b9a0. Original implementation and runtime remain on fix-local-run-readiness. This branch contains only this concern plus this task note.

# Decisions and why
Refresh provider SDKs, fetch current account-visible model catalogues, and route only the selected provider's credential into the client. Use the Responses API for current native OpenAI models, preserve compatible chat endpoints for Groq/OpenRouter, and use the shared constructor for extraction. Refresh CLI setup, custom-model validation, configured-model selection and sign-in field labels.
Keep the PR independent of the other modernization branches; do not include local recovery history, credentials or deployment overrides.

# Surprises
This isolated branch has not been built or run separately. Inference against providers without configured keys was not tested. Custom-model validation sends a short prompt and can incur provider charges. No local CI suite or browser/assistive-technology acceptance was run.

# Evidence
On the integrated implementation, six provider clients were constructed with credential isolation, Anthropic catalogue discovery succeeded, and a configured Claude model completed validation, refinement and schema-correct extraction on public synthetic input.
Validation belongs to the integrated checkout, not this independently based branch. The six source scopes together reproduce its implementation, ignoring trailing whitespace.

# Next step
Upstream consideration and independent branch validation. No merge is authorized.
