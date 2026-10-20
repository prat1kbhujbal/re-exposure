#!/usr/bin/env python3
"""agent_attack -- an iterating, tool-using RE agent, for honest cost curves.

The summary axis (agent_summary.py) is a one-shot read. This is the other half:
a real agent loop. An LLM is given a goal (recover the license key the program
checks against) and a small toolset, and it chooses one action per turn until it
recovers the key or gives up. We record how many steps it took and which tool
cracked it -- the honest "cost to recover", not a static score.

The point this measures, against the common objection that string encryption is
defeated by a debugger: it is. The agent has a `run` tool that executes the
target under an LD_PRELOAD compare-spy (tools/cmpspy.c), so a key that is XOR-
encrypted on disk is still read straight off the strcmp the moment the program
decrypts it. Static-only protection raises the step count by one or two; it does
not stop the loop. What stops it is the key not being in the client at all (a
verifier/at-runtime design) -- which this harness will score as uncracked.

The driver is a LOCAL model via Ollama (REEXPOSE_MODEL), so the agent's strength
is a floor, not a ceiling: a frontier model does at least as well. We report the
first step at which the real key became visible in a tool result (what any agent
would read off), separately from whether this particular model then typed it.

Usage:
  agent_attack.py <binary> --secret "<key>" [--max-steps 6] [--json]
  REEXPOSE_MODEL=qwen2.5-coder:32b python3 tools/agent_attack.py build/enc_o0 \
      --secret "ACME-PRO-2026-XK7Q"
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent_summary import ask, disasm, MODEL  # type: ignore

HERE = os.path.dirname(os.path.abspath(__file__))
CMPSPY_SO = os.path.join(os.path.dirname(HERE), "build", "cmpspy.so")
CMPSPY_SRC = os.path.join(HERE, "cmpspy.c")

SYSTEM = """You are an automated reverse-engineering agent. Goal: recover the \
exact license key string that the target program compares the user's input \
against.

Choose ONE action per turn. Reply with exactly one line, nothing else:

  ACTION: strings
  ACTION: disasm <function-name>
  ACTION: run <probe-string>
  ACTION: answer <the-recovered-key>

Tools:
- strings        printable strings in the binary (static).
- disasm <func>  disassembly of a function (try: disasm check_license). Omit the
                 name to list functions.
- run <probe>    execute the target with <probe> as the key, under a shim that
                 prints every string comparison's operands (dynamic analysis).
- answer <key>   submit the recovered key and stop.

You do not know the key yet. Investigate, then answer. Be efficient."""


def ensure_cmpspy() -> str | None:
    if os.path.exists(CMPSPY_SO):
        return CMPSPY_SO
    cc = "/usr/bin/gcc" if os.path.exists("/usr/bin/gcc") else "/usr/bin/cc"
    r = subprocess.run([cc, "-shared", "-fPIC", "-O2", "-o", CMPSPY_SO,
                        CMPSPY_SRC, "-ldl"], capture_output=True, text=True)
    return CMPSPY_SO if r.returncode == 0 else None


def tool_strings(binary: str) -> str:
    out = subprocess.run(["strings", "-n", "4", binary],
                         capture_output=True, text=True).stdout
    return out[:3000] or "(no strings)"


def tool_functions(binary: str) -> str:
    out = subprocess.run(["nm", "--defined-only", binary],
                         capture_output=True, text=True).stdout
    funcs = [ln.split()[-1] for ln in out.splitlines()
             if re.search(r" [Tt] ", ln)]
    return "functions: " + ", ".join(funcs[:40]) if funcs \
        else "no symbols (stripped)"


def tool_disasm(binary: str, func: str) -> str:
    if not func:
        return tool_functions(binary)
    d = disasm(binary, func)
    if d.strip():
        return d[:3000]
    return f"function '{func}' not found. " + tool_functions(binary)


def tool_run(binary: str, probe: str, spy: str | None) -> str:
    probe = probe or "PROBE-GUESS"
    env = dict(os.environ)
    if spy:
        env["LD_PRELOAD"] = spy
    r = subprocess.run([os.path.abspath(binary), probe], env=env,
                       capture_output=True, timeout=30)   # bytes: operands
    out = r.stdout.decode("utf-8", "replace")             # may be raw digests
    err = r.stderr.decode("utf-8", "replace")
    cmp_lines = [ln for ln in err.splitlines() if "CMPSPY" in ln]
    body = "stdout: " + out.strip()
    if cmp_lines:
        body += "\ncomparisons observed:\n" + "\n".join(cmp_lines[:20])
    return body[:3000]


ACTION_RE = re.compile(r"ACTION:\s*(strings|disasm|run|answer)\b[ \t]*(.*)",
                       re.IGNORECASE)


def parse_action(text: str):
    """Last ACTION line wins; tolerate the model's chatter around it."""
    last = None
    for m in ACTION_RE.finditer(text):
        last = (m.group(1).lower(), m.group(2).strip())
    return last


def attack(binary: str, secret: str, max_steps: int = 6):
    spy = ensure_cmpspy()
    transcript = []           # (action, observation)
    secret_seen_step = None
    secret_seen_tool = None
    answered = None

    for step in range(1, max_steps + 1):
        hist = "".join(f"\n[step {i+1}] ACTION: {a}\nRESULT:\n{o}\n"
                       for i, (a, o) in enumerate(transcript))
        prompt = (SYSTEM + "\n" + hist +
                  f"\nYou are on step {step} of {max_steps}. "
                  "Reply with exactly one ACTION line.\nACTION:")
        reply = ask(prompt, num_predict=160)
        act = parse_action("ACTION: " + reply)
        if not act:
            act = parse_action(reply)
        if not act:
            transcript.append(("(unparied)", "Reply was not a valid ACTION "
                               "line. Use 'ACTION: <tool> <arg>'."))
            print(f"  step {step}: unparseable reply", file=sys.stderr,
                  flush=True)
            continue

        tool, arg = act
        if tool == "answer":
            answered = arg
            print(f"  step {step}: answer {arg!r}", file=sys.stderr,
                  flush=True)
            transcript.append((f"answer {arg}", "(stopped)"))
            break
        elif tool == "strings":
            obs = tool_strings(binary)
        elif tool == "disasm":
            obs = tool_disasm(binary, arg)
        elif tool == "run":
            obs = tool_run(binary, arg, spy) if spy else \
                "run unavailable (compare-spy did not build)"
        else:
            obs = "unknown tool"

        if secret_seen_step is None and secret and secret in obs:
            secret_seen_step, secret_seen_tool = step, tool
        transcript.append((f"{tool} {arg}".strip(), obs))
        flag = "  <-- KEY VISIBLE" if secret_seen_step == step else ""
        print(f"  step {step}: {tool} {arg}".rstrip() + flag,
              file=sys.stderr, flush=True)

    return {
        "binary": binary,
        "model": MODEL,
        "steps_taken": len(transcript),
        "secret_seen_step": secret_seen_step,     # when any agent could read it
        "secret_seen_tool": secret_seen_tool,
        "answered": answered,
        "answered_correct": bool(answered and secret and secret in answered),
        "cracked": secret_seen_step is not None,
    }


def main() -> int:
    a = sys.argv[1:]
    if not a or a[0].startswith("--"):
        print(__doc__)
        return 2
    binary = a[0]
    secret = None
    if "--secret" in a:
        secret = a[a.index("--secret") + 1]
    max_steps = int(a[a.index("--max-steps") + 1]) if "--max-steps" in a else 6

    print(f"model: {MODEL}  target: {binary}  goal: recover the key",
          file=sys.stderr)
    res = attack(binary, secret, max_steps)

    if "--json" in a:
        print(json.dumps(res, indent=2))
    else:
        verdict = "CRACKED" if res["cracked"] else "not recovered from binary"
        print(f"\n{binary}: {verdict}")
        if res["cracked"]:
            print(f"  key became readable at step {res['secret_seen_step']} "
                  f"via `{res['secret_seen_tool']}`")
        print(f"  model answered correctly: {res['answered_correct']} "
              f"(answered {res['answered']!r})")
        print(f"  steps taken: {res['steps_taken']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
