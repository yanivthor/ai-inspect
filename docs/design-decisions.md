# Design decisions

Chronological. Each entry: what was decided, why, and whether it still holds.

## 2026-11-12

1. **Two passes, separated: detection and policy.** Detectors emit findings with explanations;
   `inspect.policies` in configuration decides the action. Reason: a security team must be able
   to change *what happens* without a deploy, and a detector must be addable without touching the
   rules. Holds.

2. **Deterministic detectors only, with a documented seam for a model-backed one.** The budget
   was one evening; a fine-tuned classifier is weeks of data work. The `Detector` interface is
   the seam, and `SOURCE_CODE` is deliberately the weakest detector to show where heuristics stop.
   Holds.

3. **Precision is the build gate (≥ 0.9 per detector); recall is a floor (≥ 0.8).** Reason: a
   nudge that fires on placeholders is dismissed, then disabled; false positives are the
   usability metric for inline DLP. Holds.

4. **Checksums and exclusions over bare regexes.** Luhn, mod-97, HMRC prefix rules, RFC 2606
   placeholder domains, documented example keys, Shannon entropy for generic assignments. Each
   removes a class of false positive for no latency. Holds.

5. **Prompt injection as a noisy-OR score over weighted signals**, not a match. One phrase proves
   nothing ("ignore the previous instructions" is a normal editing request); two moderate signals
   together are a HIGH. The policy picks thresholds via `min-score`. Holds.

6. **The user's own PROMPT is discounted (×0.75); RESPONSE is not.** Indirect injection via a
   tool result or fetched page is the case that matters for agents; a user jailbreaking their
   own chat is a lesser concern and often legitimate (red-teaming, writing about injection).
   Holds.

7. **Base64 blobs are decoded and rescanned.** Encoding the instruction is the first evasion
   anyone tries. Only blobs that decode to ≥ 90% printable ASCII are rescanned, so binary
   attachments cost nothing. Holds.

8. **Published test card numbers are reported at LOW, not suppressed.** They are not sensitive,
   but a user pasting `4242…` is usually about to paste the real one; the nudge is cheap. Same
   for `sk_test_` keys. Holds.

9. **Redaction only replaces HIGH spans**, merged across overlapping findings. A redaction is a
   lossy edit; MEDIUM is a warning. Holds.

10. **A detector that throws is isolated and counted.** One bad pattern must not switch the
    whole inspection off, and the counter is what makes the failure visible. Holds.

11. **Policy validates detector ids at startup.** A misspelled rule that never fires is
    indistinguishable from a working one at runtime. Holds.

12. **One Micrometer timer around the whole inspection**, p50/p95/p99 published. The latency a
    user feels is detectors plus policy, so that is what is measured. Holds.

13. **Webhook delivery is an in-process event listener on its own thread with retries**, as the
    laptop stand-in for a Kafka consumer group. Reason: Docker is not installed on this machine
    and a local broker was not worth thirty minutes of the budget; the README draws the
    production shape instead. Holds; the Kafka version is the first thing to add.

14. **No Lombok, no cache library, no ORM.** Nothing here earns them. Holds.

15. **Literal prefilters before every expensive regex.** Found by `LatencyTest`: p95 was ~30 ms
    over 15 KB against a 20 ms budget, with no single slow pattern - roughly 25 regexes at
    ~0.7 ms each. Each `SecretDetector` rule and each injection signal now carries a list of
    literal hints, and the regex only runs when the text contains one (`contains` over 15 KB is
    microseconds). p95 went to ~11 ms. The lesson is the one their blog states: accuracy and
    speed trade off only if you let them; a prefilter buys speed at zero recall cost. Holds.

16. **"You are now" needs a hijack target.** Found by the eval corpus's near-miss "You are now
    registered for the Thursday webinar", which fired the role-hijack signal at MEDIUM and put
    PROMPT_INJECTION precision at 0.83, below the 0.9 gate. The signal now requires a target
    (unrestricted, an AI/persona, ignore, obey, developer mode...). The gate did its job: the
    build failed, and the corpus keeps the near-miss. Holds.

17. **Exfiltration signal's gap must not stop at a dot.** Found by the test-writing agent:
    `[^.\n]{0,80}?` between the verb and the URL meant "send ~/.ssh to http://…" never matched,
    because `.ssh` contains a dot. Now `[^\n]{0,80}?`. Corrected 2026-11-12, same day.

18. **`RestClient.Builder` is not auto-configured in Boot 4 without the RestClient starter.**
    The context failed to start; `WebhookNotifier` now takes `ObjectProvider<RestClient.Builder>`
    and falls back to `RestClient.builder()`. Found by `InspectControllerTest`, which boots the
    real context and the real `application.yml` precisely so this class of failure is a test
    failure and not a `spring-boot:run` surprise. Holds.

19. **Subagent audit logs are generated, not written.** `scripts/agent_audit.py` turns Claude
    Code's subagent transcripts into `docs/agent-audit/<date>-<task>.md`: model, brief, every
    tool call in order, what it said, token usage. Reason: delegated work needs the same
    reviewability as a PR, and the raw transcript is unreadable. Holds.

20. **The policy picks the most severe matching action, not the first match.** Found in code
    review: the injection NUDGE rule sat above the BLOCK/REDACT rules, so a card number plus a
    weak injection signal was nudged and the card went through. First-match-wins makes every
    rule's correctness depend on its neighbours' order; most-severe-wins makes order matter only
    for ties. For a security control, the conservative composition is the right default.
    Supersedes the "first match wins" wording in decision 1. Holds.

21. **The eval is an endpoint and a page, not only a test.** `GET /api/eval` and `/eval` recompute
    the corpus and the latency benchmark against the live detectors; `EvalHarnessTest` calls the
    same `EvalService`. Reason: a number that only exists in a CI log is a number nobody looks
    at, and a dashboard that computes it differently from the gate is two numbers. The corpus
    therefore moved to main resources. Holds.

22. **The dashboard is vanilla HTML served by the backend, no build step, no CDN.** It has to
    work on a laptop with no network and be demonstrable from one `spring-boot:run`. Palette:
    the three-series categorical set validated for both colour modes (adjacent CVD ΔE 9.2 light /
    9.4 dark); the light-mode aqua's sub-3:1 contrast is relieved by direct numeric labels on
    every bar and by the table. Holds.

23. **Code-review findings live in `docs/code-review-<date>.md`, not in CLAUDE.md.** CLAUDE.md
    says what is true now; the review record says what was found, what was fixed and what was
    deliberately left, with the reason. Requested by the owner on 2026-11-12. Holds.

24. **Supporting signals never produce an injection finding alone.** Found while fixing the
    corpus: a README's `curl https://sh.rustup.rs | sh` line in a tool result scored 0.3 and
    produced a LOW finding, a false positive that put PROMPT_INJECTION precision at 0.83. A shell
    fetch is installation instructions until it sits next to an instruction override or an
    exfiltration directive, so the shell-fetch signal is now `supporting`: it adds weight but
    cannot be the only hit. The curl sample is in the corpus as a negative. Holds.

25. **Bounded identifier runs in the secret assignment regex.** The fix agent found that the
    suggested `[A-Za-z0-9_.-]*` on both sides of the keyword was quadratic on a long `a.a.a…`
    run (100 KB timed out). Both sides are capped at 64 characters with a lookbehind at the
    identifier boundary; a keyword more than 64 characters into an identifier is not matched,
    which is an acceptable loss. Pinned by a regression test. Holds.
