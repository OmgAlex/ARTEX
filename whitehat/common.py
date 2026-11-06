"""Validation shared by offline adapters. Uses only the Python standard library."""
import hashlib
import json
import re
from pathlib import Path

MAX_FILE = 64 * 1024 * 1024
MAX_DOCUMENT = 8 * 1024 * 1024
MAX_CASES = 128
MAX_RUNS = 32
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")


class Invalid(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def identifier(value):
    require(isinstance(value, str) and IDENT.fullmatch(value), "invalid identifier")
    return value


def fields(obj, required, optional=()):
    require(isinstance(obj, dict) and set(required) <= obj.keys()
            and obj.keys() <= set(required) | set(optional), "invalid or missing fields")
    return obj


def rows(value, maximum, minimum=0):
    require(isinstance(value, list) and minimum <= len(value) <= maximum, "invalid array length")
    return value


def integer(value, minimum, maximum):
    require(type(value) is int and minimum <= value <= maximum, "integer outside allowed range")
    return value


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def reject_constant(_):
        raise Invalid("invalid JSON number")
    try:
        return json.loads(data, object_pairs_hook=unique, parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Invalid("invalid JSON document") from exc


def digest(data):
    return hashlib.sha256(data).hexdigest()


def local_bytes(root, name, limit=MAX_FILE):
    require(isinstance(name, str) and len(name) < 512 and bool(name), "invalid input path")
    rel = Path(name)
    require(not rel.is_absolute() and ".." not in rel.parts, "input must be relative")
    path = (root / rel).resolve()
    require(path.is_relative_to(root) and path.is_file(), "input unavailable or outside case directory")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "input exceeds size limit")
    return data
