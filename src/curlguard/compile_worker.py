"""Resource-limited compiler. Input/output are private files owned by the caller."""

import json
import resource
import sys


def main():
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
    import yara

    with open(sys.argv[1], encoding="utf-8") as handle:
        sources = json.load(handle)
    yara.compile(sources=sources, includes=False).save(sys.argv[2])


if __name__ == "__main__":
    main()
