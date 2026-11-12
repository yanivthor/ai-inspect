package com.inspect.detect;

import com.inspect.model.Finding;
import com.inspect.model.Interaction;
import com.inspect.model.Severity;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Source code, by line-shape density: braces, semicolons, keywords and import statements.
 * <p>
 * This is the honest edge of what a heuristic can do. It separates a pasted class from prose
 * well enough, and it cannot tell proprietary code from a snippet copied off a documentation
 * page - that is a semantic judgement, and it is exactly the kind of category a small fine-tuned
 * model earns its place on. The detector reports its density as the score so the policy layer
 * can be as cautious as it likes.
 */
@Component
public class SourceCodeDetector implements Detector {

    public static final String ID = "SOURCE_CODE";

    private static final Pattern CODE_LINE = Pattern.compile(
            "^\\s*(?:(?:import|from|package|using|#include|require)\\b.*"
                    + "|(?:public|private|protected|static|final|abstract|class|interface|record|enum|def|fn|func|function|var|let|const|return|if|else|for|while|try|catch|throw)\\b.*"
                    + "|.*[;{}]\\s*$"
                    + "|.*(?:=>|->|::|==|!=|&&|\\|\\|).*"
                    + "|@\\w+(?:\\(.*\\))?\\s*)$");

    private static final Pattern LINE_BREAK = Pattern.compile("\r?\n");
    private static final int MIN_CODE_LINES = 3;
    private static final double MIN_DENSITY = 0.4;

    @Override
    public String id() {
        return ID;
    }

    @Override
    public List<Finding> detect(Interaction interaction) {
        String text = interaction.text();
        int nonBlank = 0;
        int codeLike = 0;
        int firstCodeLineOffset = -1;
        // Walk real separators so offsets stay exact with \r\n (a fixed +1 per line drifts).
        Matcher sep = LINE_BREAK.matcher(text);
        int offset = 0;
        boolean more = true;
        while (more) {
            int lineEnd;
            int next;
            if (sep.find()) { lineEnd = sep.start(); next = sep.end(); }
            else { lineEnd = text.length(); next = text.length(); more = false; }
            String line = text.substring(offset, lineEnd);
            if (!line.isBlank()) {
                nonBlank++;
                if (CODE_LINE.matcher(line).matches()) {
                    codeLike++;
                    if (firstCodeLineOffset < 0) firstCodeLineOffset = offset;
                }
            }
            offset = next;
        }
        if (nonBlank == 0 || codeLike < MIN_CODE_LINES) return List.of();
        double density = (double) codeLike / nonBlank;
        if (density < MIN_DENSITY) return List.of();

        return List.of(new Finding(ID, Severity.MEDIUM, firstCodeLineOffset, text.length(),
                codeLike + " of " + nonBlank + " lines",
                String.format("%d of %d non-blank lines have the shape of source code (%.0f%%).",
                        codeLike, nonBlank, density * 100),
                Math.min(1.0, density)));
    }
}
