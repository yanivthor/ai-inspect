# ai-inspect - project context

Inline DLP / prompt-injection inspection for text headed to an AI tool. Java 21, Spring Boot
4.1, Maven. Built 2026-11-12 in one evening as a working miniature of the two-pass
(what-is-in-it / what-to-do-about-it) engine that real AI-governance products run on device.
Read `README.md` for the API and the curl demo; this file is for anyone changing it.

```bash
./mvnw test              # unit tests + eval table + latency numbers, all must stay green
./mvnw spring-boot:run   # port 8091 (8080 and 8090 belong to sibling projects)
```

## Decisions that must survive a refactor

- **Detectors never decide an action; the policy never reads text.** The split is the product.
  A detector returns findings with an explanation; `inspect.policies` in `application.yml` maps
  findings to ALLOW/NUDGE/REDACT/BLOCK. Do not add an `action` to `Finding`.
- **Precision is the gate, not recall.** `EvalHarnessTest` fails the build on precision < 0.9
  per detector. A detector that fires on placeholders gets switched off by its users, after
  which its recall is zero anyway. Every detector has near-miss negatives in `corpus.jsonl`;
  add one for every new positive pattern you add.
- **Checksums over bare regex.** Card numbers are Luhn-checked, IBANs mod-97, NI numbers carry
  HMRC's prefix exclusions, secrets are entropy-gated. A detector that is "just a regex" needs a
  reason.
- **Prompt injection is scored, not matched.** Weighted signals combined by noisy-OR; the
  policy picks thresholds (`min-score`). The user's own PROMPT is discounted; RESPONSE text (a
  tool result, a fetched page) is where the dangerous indirect case lives.
- **A detector that throws is isolated and counted** (`inspect.detector.errors`), never allowed
  to fail the request. The contract in `Detector` says never throw; the service does not trust it.
- **The policy validates detector ids at startup.** A rule naming a detector that does not
  exist is a startup failure, because a rule that never fires looks exactly like one that works.
- **Redaction is HIGH-only.** It is a lossy edit to someone's text; MEDIUM is a warning.
- **The timer wraps detectors and policy together.** The latency a user feels is the sum.
- **Every expensive regex sits behind a literal prefilter** (`hints` on `SecretDetector.Rule`
  and `PromptInjectionDetector.Signal`). That is what took p95 from ~30 ms to ~11 ms on 15 KB.
  A new pattern without a hint needs a reason.
- **`docs/agent-audit/` is generated** by `scripts/agent_audit.py` from the subagent transcripts
  after any delegated work; name the file by task with `--name <id>=<slug>`.
- **Webhook delivery is off the request thread** and retries. In production it is a Kafka
  consumer group on the decisions topic; the single-thread executor is the laptop stand-in.

## Spring Boot 4 traps (same as the sibling projects)

- Jackson is `tools.jackson.databind.*`; only `jackson-annotations` stayed at `com.fasterxml`.
- `spring-boot-starter-jackson` must be declared explicitly.
- `@WebMvcTest` / `AutoConfigureMockMvc` moved to `org.springframework.boot.webmvc.test.autoconfigure`.
- Test starters are per-module: `spring-boot-starter-webmvc-test`, `-validation-test`.
- YAML keys containing dots (metric names) must be bracketed: `"[inspect.latency]"`.

## Working rules

- Verify against a real example before trusting a pattern. The AWS documented example key
  `AKIAIOSFODNN7EXAMPLE`, Stripe's `4242…` test card, RFC 2606's `example.com` are all in the
  corpus as negatives because real users paste them constantly.
- Keep tool output lean; grep and read ranges rather than dumping files.
- Run the `code-reviewer` subagent after a coherent change and record what it found in
  `docs/design-decisions.md`.
- Log decisions with dates and reasons in `docs/design-decisions.md`.
