#!/usr/bin/env python3
"""A stand-in for the sekret CLI's `token`, `token --context` and `login`, driven by files in
$FAKE_SEKRET_STATE:

  token          the saved token; absent means not logged in (exit 3)
  expired        present means the saved login has expired (exit 4)
  token_error    `token` fails with this text on stderr
  context.json   what `token --context` reports beside the flags it was given
  context_error  `token --context` fails with this text on stderr
  login_fails    `login` exits 1
  logins         one line per `login`
  calls          one JSON argv per call
"""

import json
import os
import sys
from pathlib import Path

FLAGS = {"--server": "server", "--project": "project", "--env": "environment", "--path": "path"}


def flags(argv):
    found = {}
    for flag, name in [*FLAGS.items(), ("--ca-file", "ca_file")]:
        if flag in argv:
            found[name] = argv[argv.index(flag) + 1]
    return found


def main():
    state = Path(os.environ["FAKE_SEKRET_STATE"])
    argv = sys.argv[1:]
    with open(state / "calls", "a") as calls:
        calls.write(json.dumps(argv) + "\n")
    given = flags(argv)
    if argv[:2] == ["token", "--context"]:
        if (state / "context_error").exists():
            sys.stderr.write((state / "context_error").read_text())
            return 1
        context = (
            json.loads((state / "context.json").read_text()) if (state / "context.json").exists() else {}
        )
        for name, value in given.items():
            context[name] = value
            context[f"{name}_source"] = "flag"
        context.setdefault("path", "/")
        context.setdefault("path_source", "default")
        print(json.dumps(context))
        return 0
    if argv[:1] == ["token"]:
        if (state / "token_error").exists():
            sys.stderr.write((state / "token_error").read_text())
            return 1
        if not (state / "token").exists():
            sys.stderr.write("sekret: not logged in\n")
            return 3
        if (state / "expired").exists():
            sys.stderr.write("sekret: expired\n")
            return 4
        print((state / "token").read_text().strip())
        return 0
    if argv[:1] == ["login"]:
        with open(state / "logins", "a") as logins:
            logins.write(given.get("server", "") + "\n")
        print(f"Open {given.get('server')}/cli-login?code=WXYZ in your browser", file=sys.stderr)
        print("Code: WXYZ", file=sys.stderr)
        if (state / "login_fails").exists():
            return 1
        count = len((state / "logins").read_text().splitlines())
        (state / "token").write_text(f"cli-token-{count}\n")
        (state / "expired").unlink(missing_ok=True)
        return 0
    sys.stderr.write(f"unexpected arguments {argv}\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
