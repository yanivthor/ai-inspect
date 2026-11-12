#!/usr/bin/env python3
"""Turn Claude Code subagent transcripts (JSONL) into a readable audit log.

Usage:
    python3 -I scripts/agent_audit.py <subagents-dir-or-jsonl> [more ...] -o docs/agent-audit \
        --name <agent-id>=<task-slug> [--name ...]

Files are named by task, not by the opaque agent id Claude Code assigns: pass
``--name <id>=<slug>``; otherwise the slug is derived from the first words of the brief. The id
stays inside the file as metadata so the transcript can still be found.

For every agent-*.jsonl it writes <out>/<agent-id>.md with: how the agent was started (model,
effort, working directory, the brief it was given), every tool call in order with a one-line
summary of its input and whether it succeeded, every message the agent wrote, and token usage.
Tool inputs and results are summarised, never copied in full, so the audit is readable and
does not reproduce file contents.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def clip(s, n):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def ts(iso):
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%H:%M:%S")
    except Exception:
        return "--:--:--"


def summarise_input(name, inp):
    if not isinstance(inp, dict):
        return clip(inp, 120)
    if name == "Bash":
        d = inp.get("description") or ""
        c = inp.get("command") or ""
        return f"{d} — `{clip(c, 110)}`" if d else f"`{clip(c, 140)}`"
    if name in ("Read", "Write", "Edit", "NotebookEdit"):
        extra = ""
        if name == "Write":
            extra = f" ({len(inp.get('content', ''))} chars)"
        if name == "Edit":
            extra = f" (−{len(inp.get('old_string', ''))}/+{len(inp.get('new_string', ''))} chars)"
        if name == "Read" and (inp.get("offset") or inp.get("limit")):
            extra = f" (offset {inp.get('offset')}, limit {inp.get('limit')})"
        return f"{inp.get('file_path', '?')}{extra}"
    if name in ("Grep", "Glob"):
        return f"pattern `{clip(inp.get('pattern', ''), 60)}` in {inp.get('path') or inp.get('glob') or '.'}"
    if name == "Agent":
        return f"{inp.get('subagent_type', 'general')} / {inp.get('model', 'default')}: {clip(inp.get('description', ''), 60)}"
    if name == "TodoWrite":
        todos = inp.get("todos", [])
        return f"{len(todos)} items: " + "; ".join(clip(t.get("content", ""), 40) for t in todos[:4])
    return clip(json.dumps(inp, ensure_ascii=False), 140)


def summarise_result(block):
    content = block.get("content")
    if isinstance(content, list):
        text = " ".join(c.get("text", "") for c in content if isinstance(c, dict))
    else:
        text = str(content or "")
    status = "ERROR" if block.get("is_error") else "ok"
    return status, len(text), clip(text, 100)


def slugify(text, words=6):
    out = []
    for w in text.split():
        w = "".join(ch for ch in w.lower() if ch.isalnum())
        if w:
            out.append(w)
        if len(out) == words:
            break
    return "-".join(out) or "agent"


def audit(path: Path, out_dir: Path, names: dict):
    rows = []
    texts = []
    started = None
    model = effort = cwd = brief = agent_id = None
    usage_in = usage_out = cache_read = cache_write = 0
    requests = 0
    pending = {}  # tool_use_id -> row index

    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = o.get("type")
            agent_id = agent_id or o.get("agentId")
            if t == "user" and brief is None and not o.get("isMeta"):
                started = o.get("timestamp")
                cwd = o.get("cwd")
                m = o.get("message", {})
                c = m.get("content")
                if isinstance(c, list):
                    c = " ".join(x.get("text", "") for x in c if isinstance(x, dict))
                brief = str(c or "")
            elif t == "assistant":
                requests += 1
                model = model or o.get("message", {}).get("model") or o.get("requestedModel")
                effort = effort or o.get("effort")
                u = o.get("message", {}).get("usage") or {}
                usage_in += u.get("input_tokens", 0) or 0
                usage_out += u.get("output_tokens", 0) or 0
                cache_read += u.get("cache_read_input_tokens", 0) or 0
                cache_write += u.get("cache_creation_input_tokens", 0) or 0
                for block in o.get("message", {}).get("content", []) or []:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "tool_use" and block.get("name") == "SubagentHandback":
                        # The agent's final report travels as a tool call, not prose.
                        report = block.get("input", {}).get("report") or block.get("input", {}).get("message") \
                            or json.dumps(block.get("input", {}), ensure_ascii=False)
                        texts.append((ts(o.get("timestamp", "")), "**Final report:** " + clip(report, 4000)))
                    if block.get("type") == "tool_use":
                        rows.append({
                            "time": ts(o.get("timestamp", "")),
                            "tool": block.get("name"),
                            "input": summarise_input(block.get("name"), block.get("input")),
                            "status": "pending", "result_len": 0, "result": "",
                        })
                        pending[block.get("id")] = len(rows) - 1
                    elif block.get("type") == "text" and block.get("text", "").strip():
                        texts.append((ts(o.get("timestamp", "")), clip(block["text"], 400)))
            elif t == "user" and o.get("toolUseResult") is not None or (
                t == "user" and isinstance(o.get("message", {}).get("content"), list)
                and any(isinstance(b, dict) and b.get("type") == "tool_result" for b in o["message"]["content"])
            ):
                for block in o.get("message", {}).get("content", []) or []:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        idx = pending.get(block.get("tool_use_id"))
                        if idx is not None:
                            status, n, excerpt = summarise_result(block)
                            rows[idx].update(status=status, result_len=n, result=excerpt)

    agent = path.stem.replace("agent-", "")
    day = (started or "")[:10] or "undated"
    task = names.get(agent) or slugify(brief or "")
    out = out_dir / f"{day}-{task}.md"
    with out.open("w") as w:
        w.write(f"# Subagent audit: {task.replace('-', ' ')}\n\n")
        w.write(f"- **Agent id (Claude Code's, opaque):** `{agent}`\n")
        w.write(f"- **Transcript:** `{path}`\n")
        w.write(f"- **Started:** {started or 'unknown'}\n")
        w.write(f"- **Model:** {model or 'unknown'}  ·  **effort:** {effort or 'default'}\n")
        w.write(f"- **Working directory:** `{cwd or 'unknown'}`\n")
        w.write(f"- **API requests:** {requests}  ·  **tokens:** {usage_in:,} in / {usage_out:,} out"
                f" / {cache_read:,} cache-read / {cache_write:,} cache-write\n")
        w.write(f"- **Tool calls:** {len(rows)}"
                f" ({sum(1 for r in rows if r['status'] == 'ERROR')} errors,"
                f" {sum(1 for r in rows if r['status'] == 'pending')} unresolved)\n\n")
        w.write("## Brief given to the agent\n\n")
        w.write("> " + clip(brief or "", 1200).replace("\n", " ") + "\n\n")
        w.write("## Steps, in order\n\n")
        w.write("| # | Time (UTC) | Tool | Input | Result |\n|---|---|---|---|---|\n")
        for i, r in enumerate(rows, 1):
            res = f"{r['status']}" + (f", {r['result_len']} chars" if r["result_len"] else "")
            if r["status"] == "ERROR":
                res += f": {r['result']}"
            w.write(f"| {i} | {r['time']} | {r['tool']} | {r['input'].replace('|', '\\|')} | {res.replace('|', '\\|')} |\n")
        w.write("\n## What the agent said\n\n")
        for time, text in texts:
            w.write(f"- **{time}** {text}\n")
        if not texts:
            w.write("_(no prose messages yet)_\n")
    return out, len(rows), requests


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("-o", "--out", default="docs/agent-audit")
    ap.add_argument("--name", action="append", default=[], metavar="ID=SLUG",
                    help="name the audit file for agent ID by task SLUG")
    a = ap.parse_args()
    names = dict(n.split("=", 1) for n in a.name)
    out_dir = Path(a.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    files = []
    for p in a.paths:
        p = Path(p)
        if p.is_dir():
            files += sorted(p.glob("agent-*.jsonl"))
        elif p.exists():
            files.append(p)
    if not files:
        sys.exit("no transcripts found")
    index = []
    for f in files:
        out, n_tools, n_req = audit(f, out_dir, names)
        index.append((out.name, n_tools, n_req))
        print(f"wrote {out} ({n_tools} tool calls, {n_req} requests)")
    with (out_dir / "README.md").open("w") as w:
        w.write("# Subagent audit logs\n\nGenerated by `scripts/agent_audit.py` from the Claude Code subagent "
                "transcripts. One file per agent: how it was started, every tool call in order, "
                "what it said, and token usage.\n\n")
        for name, n_tools, n_req in index:
            w.write(f"- [{name}]({name}) — {n_tools} tool calls over {n_req} model requests\n")


if __name__ == "__main__":
    main()
