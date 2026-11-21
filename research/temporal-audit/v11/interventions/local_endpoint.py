"""A local teaching executable. Read one synthetic request from stdin and write UTF-8 to stdout."""
import argparse
import json
import os
import re
import sys

TOKEN = re.compile(r"SPE-[0-9a-f]{32}")
PREFIX = "Fictional archive ticket: "
NONE = "No ticket supplied."
GENERIC = "This is a fictional archive."


def answer(payload, mode, side_value=None):
    request = json.loads(payload.decode("utf-8"))
    if mode == "generic":
        return GENERIC
    if mode == "side":
        if not isinstance(side_value, str) or not TOKEN.fullmatch(side_value):
            raise ValueError("missing synthetic control value")
        return side_value
    if mode != "reader":
        raise ValueError("unknown local operating mode")
    for doc in request["sources"]:
        if doc["text"].startswith(PREFIX):
            ticket = doc["text"][len(PREFIX):]
            if TOKEN.fullmatch(ticket):
                return ticket
    return NONE


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["reader", "generic", "side"])
    args = parser.parse_args()
    result = answer(sys.stdin.buffer.read(), args.mode, os.environ.get("SPE_FIXTURE_SIDE_VALUE"))
    sys.stdout.buffer.write(result.encode("utf-8"))
