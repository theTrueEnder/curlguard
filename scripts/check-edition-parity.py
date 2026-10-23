"""Release gate: shared trees must match except for exact edition defaults/text."""

import argparse
import subprocess


def git(*arguments):
    return subprocess.check_output(["git", *arguments])


def check(general, security):
    general, security = (
        git("rev-parse", "--verify", "--end-of-options", ref + "^{commit}")
        .decode()
        .strip()
        for ref in (general, security)
    )
    paths = git("diff", "--name-only", "-z", general, security).split(b"\0")
    unexpected = set(paths) - {b"", b"README.md", b"src/curlguard/edition.py"}
    if unexpected:
        raise ValueError(
            f"shared trees differ: {sorted(p.decode() for p in unexpected)}"
        )
    for ref, edition, strict, other in (
        (general, "general-users", False, "security"),
        (security, "security-users", True, "general"),
    ):
        module = git("show", f"{ref}:src/curlguard/edition.py").decode()
        expected = (
            '"""Shipped defaults; variant branches change only this module."""\n\n'
            f'EDITION = "{edition}"\nSECURITY = {strict}\n'
        )
        if module != expected:
            raise ValueError(f"unexpected defaults for {edition}")
        readme = git("show", f"{ref}:README.md").decode()
        audience = (
            f"The current branch is **codex/{edition}**. The maintained {other} variant is\n"
            f"**codex/{other}-users**."
        )
        if readme.count(audience) != 1:
            raise ValueError(f"unexpected audience text for {edition}")
        normalized = readme.replace(audience, "EDITION AUDIENCE")
        if edition == "general-users":
            baseline = normalized
        elif normalized != baseline:
            raise ValueError("README differs beyond the edition audience statement")
    print(f"Edition parity passed: general={general} security={security}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("general")
    parser.add_argument("security")
    args = parser.parse_args()
    try:
        check(args.general, args.security)
    except (ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Edition parity failed: {exc}\n")


if __name__ == "__main__":
    main()
