#!/usr/bin/env python3
"""Lint whitelist.yaml.

usage: lint.py <whitelist.yaml> <public_suffix_list.dat> <public-suffix-exceptions.txt>

The public suffix list comes from https://github.com/publicsuffix/list; the
revision CI uses is pinned in .github/workflows/lint.yml.
"""
import os
import re
import sys

import yaml

LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
HOSTNAME = re.compile(rf"(?:{LABEL}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{1,59}})")

whitelist_path, psl_path, exceptions_path = sys.argv[1:4]
problems = []


def format_problem(entry):
    base = entry.removeprefix("*.")
    if re.search(r"\s", entry):
        return "contains whitespace"
    if "/" in entry:
        return "must be a hostname, not a URL or path"
    if ":" in entry:
        return "must be a hostname without a port"
    if entry != entry.lower():
        return "must be lowercase"
    if "*" in base:
        return 'may only use a wildcard as a leading "*."'
    if entry.endswith("."):
        return "must not end with a dot"
    if entry.startswith("*.") and "." not in base:
        return "is a wildcard on a whole top-level domain"
    if not HOSTNAME.fullmatch(base):
        return "is not a valid hostname"
    return None


def load_public_suffixes(path):
    exact, wildcard, exception = set(), set(), set()
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0].lower()
            target = exception if rule.startswith("!") else wildcard if rule.startswith("*.") else exact
            name = rule.lstrip("!").removeprefix("*.")
            try:
                name = name.encode("idna").decode("ascii")
            except UnicodeError:
                pass
            target.add(name)
    return exact, wildcard, exception


def public_suffix_problem(base, exact, wildcard, exception):
    parent = base.split(".", 1)[1]
    if base in exact or (parent in wildcard and base not in exception):
        return f"{base} is a public suffix"
    # a wildcard matches at any depth, so it also reaches suffixes below its base
    covered = sorted(s for s in exact if s.endswith("." + base))
    covered += sorted("*." + r for r in wildcard if r == base or r.endswith("." + base))
    if covered:
        more = f" and {len(covered) - 1} more" if len(covered) > 1 else ""
        return f"it covers the public suffix {covered[0]}{more}"
    return None


groups, entries = {}, {}
root = None
try:
    with open(whitelist_path, encoding="utf-8") as f:
        root = yaml.compose(f.read())
    if root is None:
        problems.append((whitelist_path, 1, "file is empty"))
except yaml.YAMLError as e:
    mark = getattr(e, "problem_mark", None)
    hint = ' (a wildcard must be quoted: "*.example.com")' if "alias" in str(e) else ""
    problems.append((whitelist_path, mark.line + 1 if mark else 1, f"not valid YAML: {getattr(e, 'problem', e)}{hint}"))

if root is not None and not isinstance(root, yaml.MappingNode):
    problems.append((whitelist_path, 1, "top level must map group names to lists of hostnames"))
    root = None

for key, value in root.value if root is not None else []:
    line = key.start_mark.line + 1
    if not isinstance(key, yaml.ScalarNode):
        problems.append((whitelist_path, line, "group name must be a plain string"))
        continue
    if key.value in groups:
        problems.append((whitelist_path, line, f"group {key.value!r} is already defined on line {groups[key.value]}; YAML keeps only the last one"))
    groups.setdefault(key.value, line)
    if not isinstance(value, yaml.SequenceNode) or not value.value:
        problems.append((whitelist_path, line, f"group {key.value!r} must be a non-empty list of hostnames"))
        continue
    for item in value.value:
        line = item.start_mark.line + 1
        if not isinstance(item, yaml.ScalarNode) or item.tag != "tag:yaml.org,2002:str":
            problems.append((whitelist_path, line, "entry must be a hostname string"))
            continue
        entry = item.value
        reason = format_problem(entry)
        if reason:
            problems.append((whitelist_path, line, f"{entry!r} {reason}"))
        elif entry in entries:
            problems.append((whitelist_path, line, f"{entry!r} is a duplicate of line {entries[entry]}"))
        else:
            entries[entry] = line

if root is not None:
    suffixes = load_public_suffixes(psl_path)
    allowed = {}
    with open(exceptions_path, encoding="utf-8") as f:
        for number, raw in enumerate(f, 1):
            exception = raw.split("#")[0].strip()
            if exception:
                allowed[exception] = number
    used = set()
    for entry, line in entries.items():
        reason = public_suffix_problem(entry[2:], *suffixes) if entry.startswith("*.") else None
        if reason and entry in allowed:
            used.add(entry)
        elif reason:
            problems.append((whitelist_path, line, f"{entry!r}: {reason}, so anyone can get a hostname under it. List the exact hosts instead, or add the wildcard to {exceptions_path} if it is really needed"))
    for exception, number in allowed.items():
        if exception not in used:
            problems.append((exceptions_path, number, f"{exception!r} matches no public-suffix wildcard in {whitelist_path}; remove it"))

in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
for path, line, message in sorted(problems):
    if in_actions:
        data = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error file={path},line={line}::{data}")
    else:
        print(f"{path}:{line}: {message}")
if problems:
    sys.exit(1)
print(f"{whitelist_path}: OK, {len(entries)} entries in {len(groups)} groups")
