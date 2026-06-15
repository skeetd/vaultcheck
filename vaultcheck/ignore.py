"""Shared ignore + inline-suppression logic for all scanners.

Two mechanisms, both consulted by the secrets, code and dependency scanners so
behaviour is consistent:

1. Path ignores via a `.vaultcheckignore` file at the scan root (gitignore-style
   globs). A small set of sensible defaults is always applied (test fixtures,
   examples, vendored deps) unless `--no-default-ignores` disables them. Patterns
   match against the POSIX relative path; a trailing `/` matches a directory and
   everything under it.

2. Inline suppression: a `nosec` token in a line-level comment suppresses findings
   on that line. Optionally scoped:
       foo = "AKIA..."        # nosec            -> suppress everything on this line
       eval(x)                # nosec code       -> suppress only code-scanner findings
       secret = "..."         # nosec secret     -> suppress only secret findings
   Recognised scopes: secret, code, dep (aliases: secrets, deps). No scope = all.

The goal is to silence the inevitable self-matches (a scanner detecting its own
regex patterns, or known-safe test data) without hiding real findings.
"""
import re
from pathlib import Path
from typing import Optional

# Always-on unless the caller opts out. Kept deliberately small and conventional.
DEFAULT_IGNORES = [
    "**/test/fixtures/**",
    "**/tests/fixtures/**",
    "**/testdata/**",
    "**/__fixtures__/**",
    "examples/**",
    "**/*.min.js",
    "**/vendor/**",
    "**/node_modules/**",
]

IGNORE_FILENAME = ".vaultcheckignore"

# nosec[: scope1, scope2] inside a comment. We only require the token to appear;
# scope parsing is best-effort.
_NOSEC_RE = re.compile(r"(?:#|//|/\*|<!--)\s*nosec\b([^\n]*)", re.IGNORECASE)
_SCOPE_ALIASES = {"secret": "secret", "secrets": "secret",
                  "code": "code",
                  "dep": "dep", "deps": "dep", "dependency": "dep"}


class IgnoreRules:
    """Resolved ignore configuration for one scan root."""

    def __init__(self, patterns: list[str]):
        # Normalise: strip blanks/comments, unify separators.
        self.patterns: list[str] = []
        for p in patterns:
            p = p.strip()
            if not p or p.startswith("#"):
                continue
            self.patterns.append(p.replace("\\", "/"))

    def match(self, rel_path: str) -> bool:
        rel = rel_path.replace("\\", "/")
        for pat in self.patterns:
            if _match_one(pat, rel):
                return True
        return False


def _match_one(pattern: str, rel: str) -> bool:
    # Directory pattern: "foo/" matches foo and anything beneath it.
    if pattern.endswith("/"):
        base = pattern.rstrip("/")
        return rel == base or rel.startswith(base + "/")

    # A leading "**/" should match zero or more leading directories, so also try
    # the pattern with that prefix removed (fnmatch's '*' won't cross the first
    # path boundary on its own).
    candidates = [pattern]
    if pattern.startswith("**/"):
        candidates.append(pattern[3:])

    for pat in candidates:
        if _regex_match(pat, rel):
            return True
        # bare segment ("foo") matches that segment anywhere in the path
        if "/" not in pat and any(_regex_match(pat, seg) for seg in rel.split("/")):
            return True
        # "examples/**" should also catch the bare directory "examples"
        if pat.endswith("/**"):
            base = pat[:-3]
            if rel == base or rel.startswith(base + "/"):
                return True
    return False


def _regex_match(pattern: str, rel: str) -> bool:
    """Glob match where '**' spans path separators and '*' does not."""
    # Build a regex: ** -> .* , * -> [^/]* , ? -> [^/]
    out = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if pattern[i:i + 2] == "**":
                out.append(".*")
                i += 2
                if pattern[i:i + 1] == "/":  # "**/" consumes the slash too
                    i += 1
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    return re.fullmatch("".join(out), rel) is not None


def load_ignore_rules(root: Path, use_defaults: bool = True) -> IgnoreRules:
    patterns: list[str] = list(DEFAULT_IGNORES) if use_defaults else []
    ignore_file = root / IGNORE_FILENAME
    if ignore_file.exists():
        try:
            patterns += ignore_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            pass
    return IgnoreRules(patterns)


def nosec_scopes(line: str) -> Optional[set]:
    """Return the suppression scopes for a line, or None if no nosec present.

    Empty set means "suppress all scopes". A populated set restricts suppression
    to those scopes (e.g. {"code"}).
    """
    m = _NOSEC_RE.search(line)
    if not m:
        return None
    tail = m.group(1).lower()
    scopes = set()
    for tok in re.split(r"[,\s]+", tail):
        tok = tok.strip(": ")
        if tok in _SCOPE_ALIASES:
            scopes.add(_SCOPE_ALIASES[tok])
    return scopes  # empty => all scopes suppressed


def line_suppressed(line: str, scope: str) -> bool:
    """True if `line` carries a nosec that covers `scope` ('secret'|'code'|'dep')."""
    scopes = nosec_scopes(line)
    if scopes is None:
        return False
    return not scopes or scope in scopes
