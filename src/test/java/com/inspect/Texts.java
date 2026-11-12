package com.inspect;

import com.inspect.model.Channel;
import com.inspect.model.Direction;
import com.inspect.model.Interaction;

/** Test helpers for building interactions. */
public final class Texts {
    private Texts() {}

    public static Interaction prompt(String text) {
        return new Interaction("t-1", "dave", "claude.ai", Channel.BROWSER, Direction.PROMPT, text);
    }

    public static Interaction response(String text) {
        return new Interaction("t-1", "dave", "mcp-server", Channel.MCP, Direction.RESPONSE, text);
    }

    public static Interaction of(Direction direction, String destination, String text) {
        return new Interaction("t-1", "dave", destination, Channel.BROWSER, direction, text);
    }
}
