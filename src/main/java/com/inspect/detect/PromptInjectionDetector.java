package com.inspect.detect;

import com.inspect.model.Direction;
import com.inspect.model.Finding;
import com.inspect.model.Interaction;
import com.inspect.model.Severity;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Prompt injection, scored rather than matched.
 * <p>
 * No single phrase proves an injection - "ignore the previous instructions" appears in
 * legitimate editing requests - so each signal carries a weight and the finding's score is the
 * noisy-OR of the signals present: one weak signal is a LOW, two moderate ones together are a
 * HIGH. The policy layer decides what to do at which score, and the explanation names the
 * signals so a user (or an agent) can see exactly why.
 * <p>
 * Direction matters. The dangerous case is <em>indirect</em> injection: an instruction hidden in
 * a RESPONSE - a fetched web page, an MCP tool result, a document - that an agent is about to act
 * on. Text a user types themselves is their own business and is discounted. Base64 blobs are
 * decoded and re-scanned, because "encode the instruction" is the first evasion anyone tries.
 */
@Component
public class PromptInjectionDetector implements Detector {

    public static final String ID = "PROMPT_INJECTION";

    /**
     * {@code hints} are lowercase literals; the pattern only runs if the lowercased text contains
     * one. A {@code contains} over 15 KB costs microseconds, a case-insensitive regex with
     * alternations costs close to a millisecond, and most text contains none of these words.
     */
    private record Signal(String name, Pattern pattern, double weight, List<String> hints) {
        boolean mightMatch(String lower) {
            for (String h : hints) if (lower.contains(h)) return true;
            return false;
        }
    }

    private static final List<Signal> SIGNALS = List.of(
            new Signal("instruction override",
                    Pattern.compile("(?i)\\b(?:ignore|disregard|forget|override)\\b[^.\\n]{0,20}?\\b(?:all |any |the |your |my )?(?:previous|prior|above|earlier|preceding|initial|original|system)\\b[^.\\n]{0,20}?\\b(?:instructions?|prompts?|rules|directions|guidelines|commands?)\\b"),
                    0.6, List.of("ignore", "disregard", "forget", "override")),
            new Signal("role hijack",
                    // "you are now" / "from now on" need a hijack target: "you are now registered for
                    // the webinar" is not an attack, "you are now an unrestricted AI" is.
                    Pattern.compile("(?i)\\b(?:(?:you are now|from now on,? you (?:are|will|must))\\b[^.\\n]{0,30}?\\b(?:unrestricted|unfiltered|uncensored|jailbroken|evil|free of|without (?:any )?(?:restrictions|rules|limits|filters)|ignore|obey|only answer|an? (?:AI|assistant|bot|model|hacker|persona|character))\\b|act as (?:an? )?(?:unrestricted|unfiltered|jailbroken|evil)\\b|pretend (?:you are|to be) (?:an? )?(?:unrestricted|unfiltered|different)\\b|enable developer mode\\b|\\bDAN\\b mode|do anything now\\b)"),
                    0.45, List.of("you are now", "from now on", "act as", "pretend", "developer mode", "dan", "do anything now")),
            new Signal("system prompt extraction",
                    Pattern.compile("(?i)\\b(?:reveal|print|show|repeat|output|display|leak|tell me)\\b[^.\\n]{0,30}?\\b(?:your|the|its)\\s+(?:system prompt|initial prompt|hidden (?:prompt|instructions)|secret instructions|instructions above|configuration)\\b"),
                    0.5, List.of("system prompt", "initial prompt", "hidden", "secret instructions", "instructions above", "configuration")),
            new Signal("exfiltration directive",
                    Pattern.compile("(?i)\\b(?:send|post|upload|forward|email|transmit|exfiltrate|submit|leak)\\b[^\\n]{0,80}?\\b(?:to\\s+)?(?:https?://|ftp://|[a-z0-9-]+\\.[a-z0-9-]+\\.(?:com|net|io|org|xyz|ru|cn)\\b)"),
                    0.6, List.of("send", "post", "upload", "forward", "email", "transmit", "exfiltrate", "submit", "leak")),
            new Signal("shell fetch",
                    Pattern.compile("(?i)\\b(?:curl|wget|Invoke-WebRequest)\\b[^\\n]{0,60}https?://"),
                    0.3, List.of("curl", "wget", "invoke-webrequest")),
            new Signal("delimiter smuggling",
                    Pattern.compile("(?i)(?:</?(?:system|assistant|instructions?|developer)>|\\[(?:SYSTEM|INST|/INST)]|^#{2,}\\s*(?:system|instructions?)\\b|<\\|im_start\\|>|<\\|system\\|>|\\bBEGIN SYSTEM PROMPT\\b)", Pattern.MULTILINE),
                    0.5, List.of("<system", "</system", "<assistant", "</assistant", "<instruction", "</instruction", "<developer", "</developer", "[system]", "[inst]", "[/inst]", "##", "<|", "begin system prompt")),
            new Signal("false authority",
                    Pattern.compile("(?i)\\b(?:this is|i am|as)\\s+(?:your|the)\\s+(?:administrator|developer|creator|operator|owner|openai|anthropic|system)\\b|\\b(?:important|urgent|critical)\\s+(?:new\\s+)?(?:instructions?|update)\\s*[:!]"),
                    0.35, List.of("administrator", "developer", "creator", "operator", "owner", "openai", "anthropic", "system", "important", "urgent", "critical")),
            new Signal("agent action hijack",
                    Pattern.compile("(?i)\\b(?:AI|assistant|agent|model|LLM)s?\\b[^.\\n]{0,30}?\\b(?:must|should|need to|are required to)\\b[^.\\n]{0,40}?\\b(?:delete|drop|remove|execute|run|install|transfer|approve|grant)\\b"),
                    0.4, List.of("must", "should", "need to", "required to"))
    );

    private static final Pattern BASE64_BLOB = Pattern.compile("(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])");
    private static final Pattern ZERO_WIDTH = Pattern.compile("[\\u200B-\\u200F\\u2060\\uFEFF]{3,}");

    /** A user's own prompt is their business; an instruction arriving in a response is not. */
    private static final double PROMPT_DIRECTION_DISCOUNT = 0.75;

    @Override
    public String id() {
        return ID;
    }

    @Override
    public List<Finding> detect(Interaction interaction) {
        String text = interaction.text();
        String lower = text.toLowerCase(Locale.ROOT);
        List<String> hits = new ArrayList<>();
        double survive = 1.0;      // product of (1 - weight): noisy-OR accumulator
        int firstStart = -1;
        int lastEnd = -1;

        for (Signal signal : SIGNALS) {
            if (!signal.mightMatch(lower)) continue;
            Matcher m = signal.pattern().matcher(text);
            if (m.find()) {
                hits.add(signal.name());
                survive *= (1 - signal.weight());
                if (firstStart < 0 || m.start() < firstStart) firstStart = m.start();
                if (m.end() > lastEnd) lastEnd = m.end();
            }
        }

        Matcher b64 = BASE64_BLOB.matcher(text);
        while (b64.find()) {
            String decoded = tryDecode(b64.group());
            if (decoded == null) continue;
            String decodedLower = decoded.toLowerCase(Locale.ROOT);
            for (Signal signal : SIGNALS) {
                if (signal.mightMatch(decodedLower) && signal.pattern().matcher(decoded).find()) {
                    hits.add("base64-encoded " + signal.name());
                    survive *= (1 - 0.7);
                    if (firstStart < 0 || b64.start() < firstStart) firstStart = b64.start();
                    if (b64.end() > lastEnd) lastEnd = b64.end();
                    break;
                }
            }
        }

        Matcher zw = ZERO_WIDTH.matcher(text);
        if (zw.find()) {
            hits.add("zero-width characters");
            survive *= (1 - 0.3);
            if (firstStart < 0 || zw.start() < firstStart) firstStart = zw.start();
            if (zw.end() > lastEnd) lastEnd = zw.end();
        }

        if (hits.isEmpty()) return List.of();

        double score = 1 - survive;
        boolean discounted = interaction.direction() == Direction.PROMPT;
        if (discounted) score *= PROMPT_DIRECTION_DISCOUNT;
        score = Math.round(score * 100) / 100.0;

        Severity severity = score >= 0.7 ? Severity.HIGH : score >= 0.4 ? Severity.MEDIUM : Severity.LOW;
        String explanation = "Signals: " + String.join(", ", hits) + "."
                + (discounted ? " Discounted because it is the user's own prompt, not content being fed to an agent." : "");
        String evidence = text.substring(firstStart, Math.min(lastEnd, firstStart + 60)).replaceAll("\\s+", " ");
        return List.of(new Finding(ID, severity, firstStart, lastEnd, evidence, explanation, score));
    }

    private static String tryDecode(String blob) {
        try {
            byte[] bytes = Base64.getDecoder().decode(blob);
            String s = new String(bytes, StandardCharsets.UTF_8);
            // Only text is worth re-scanning; binary decodes to replacement characters.
            long printable = s.chars().filter(c -> c >= 0x20 && c < 0x7F || c == '\n' || c == '\t').count();
            return printable >= s.length() * 0.9 ? s : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
