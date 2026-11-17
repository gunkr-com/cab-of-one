"""Protected-path and approval-command scanner for Bash text (S4 guard step 2).

Independent of the S3 lexer on purpose: S3 decides read/write for the tenant, this module
decides whether a command touches the harness's own files or runs a human-only ``cab``
command. It is best effort against mistakes, not a sandbox (DESIGN §3-10).

Rules
- Any text (the command, nested ``bash -c`` text, substitutions, here-documents, inline
  programs, scripts it can read) naming ``cab`` / ``cab_of_one`` followed on the same line
  by ``approve``, ``ack``, ``resume``, ``intake`` or ``setup ... apply|uninstall``, or
  naming a pseudo-terminal helper together with ``cab``: ``approval_cmd``. (The exact
  literal fixture intake call of the pinned CLI never reaches this scan: guard step 1a.)
- Redirections, ``tee``, ``cp``/``mv``/``install``/``rsync``/``ln`` destinations,
  ``rm``/``rmdir``/``unlink``, ``truncate``, ``touch``, ``chmod``-family, ``mkdir``, ``dd of=``,
  ``sed -i``/``perl -i`` files, ``sort -o``, ``find -delete``/``-fprint``, ``git rm/mv/
  restore/checkout/clean`` paths: a protected target is ``protected_path``; a target the
  shell would compute at run time (``$``, backticks, glob, braces, ``~``, a relative path
  after a non-literal ``cd``) is ``opaque_write``.
- Inline programs (``python -c``, ``node -e``, ``pwsh -Command`` ...) and scripts are read
  (project files only, 256 KiB); harness path fragments in them, or a script that cannot be
  read, is ``opaque_script``.
- Other programs: a literal operand naming a protected path is ``protected_path`` unless
  the program is a known read-only tool. Text the scanner cannot split is refused only
  when it names harness paths.

Literal edits of other files stay possible.
"""

from __future__ import annotations

import os
import posixpath
import re
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass, field

__all__ = [
    "APPROVAL",
    "OPAQUE_SCRIPT",
    "OPAQUE_WRITE",
    "PROTECTED",
    "ParseError",
    "ScanContext",
    "approval_text",
    "binding_safe",
    "intake_text",
    "parse",
    "scan",
    "subagent_command_ok",
]

APPROVAL = "approval_cmd"
PROTECTED = "protected_path"
OPAQUE_WRITE = "opaque_write"
OPAQUE_SCRIPT = "opaque_script"

MAX_DEPTH = 8
MAX_TEXT = 256 * 1024

_CAB_WORD = re.compile(r"(?i)(?<![\w.-])cab(?:\.py)?(?![\w-])|cab_of_one")
_APPROVAL_VERB = re.compile(r"(?i)\b(?:approve|ack|resume)\b")
# ``intake`` as a word of its own (not ``intake.md``, ``change-intake`` or a path part).
_INTAKE_VERB = re.compile(r"(?i)(?<![\w./-])intake(?![\w./-])")
_SETUP_VERB = re.compile(r"(?i)\bsetup\b.*?\b(?:apply|uninstall)\b")
_PTY_WORD = re.compile(r"(?i)(?<![\w.-])(?:script|expect|unbuffer|socat|tmux|screen|pty)(?![\w-])")
_FRAGMENTS = re.compile(
    r"(?i)(?:approval|review|verify|snapshot)\.json"
    r"|approvals\.(?:jsonl|lock)"
    r"|(?<![\w-])\.cab(?![\w-])"
    r"|(?<![\w.-])policy[/\\]|policy\.toml|standard-changes"
    r"|(?<![\w.-])audit[/\\]|[/\\]ledger\b"
    r"|(?<![\w-])\.claude(?![\w-])"
    r"|cab-of-one|cab_of_one"
)
_COMPONENTS = re.compile(r"(?i)(?<![\w.-])(?:\.claude|policy|audit|\.cab)(?![\w-])")
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")
_SINKS = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"})

_REDIR_OPS = ("&>>", "<<<", "<<-", "&>", ">>", ">|", ">&", "<&", "<>", "<<", ">", "<")
_SEP_OPS = (";;&", "&&", "||", "|&", ";;", ";&", "|", "&", ";")
OUTPUT_OPS = frozenset({">", ">>", ">|", "&>", "&>>", "<>"})
_HEREDOC_OPS = frozenset({"<<", "<<-"})

_KEYWORDS_SKIP = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "{"})
_KEYWORDS_STOP = frozenset({"fi", "done", "esac", "}", "for", "select", "case", "function", "in"})
_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "fish"})
_PYTHON = re.compile(r"^python[0-9.]*$")
_INTERPRETERS = frozenset(
    {
        "node", "nodejs", "deno", "bun", "ruby", "perl", "php", "lua", "rscript",
        "osascript", "tclsh", "wish", "expect", "pwsh", "powershell", "awk", "gawk",
        "mawk", "nawk", "npx", "uv", "uvx",
    }
)  # fmt: skip
_READ_ONLY = frozenset(
    {
        "cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "ag", "wc",
        "ls", "stat", "file", "diff", "cmp", "comm", "shasum", "sha1sum", "sha256sum",
        "sha512sum", "md5", "md5sum", "cksum", "b2sum", "jq", "od", "hexdump", "strings",
        "nl", "column", "cut", "tr", "readlink", "realpath", "basename", "dirname", "test",
        "[", "echo", "printf", "true", "false", "pwd", "which", "type", "du", "df",
        "date", "sleep", "whoami", "id", "uname", "printenv", "sort", "uniq", "tree",
        "read", "set", "unset", "export", "declare", "typeset", "local", "readonly",
        "exit", "return", "shift", "wait", "jobs", "umask", "alias", "unalias", "hash",
        "shopt",
    }
)  # fmt: skip
_WRAPPERS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    # name: (options that take a value, options that change the working directory)
    "sudo": (
        frozenset({"-u", "-g", "-C", "-p", "-U", "-h", "-r", "-t", "-T", "--user", "--group"}),
        frozenset({"-D", "-R", "--chdir", "--chroot"}),
    ),
    "doas": (frozenset({"-u", "-C"}), frozenset()),
    "env": (frozenset({"-u", "--unset"}), frozenset({"-C", "--chdir"})),
    "nice": (frozenset({"-n", "--adjustment"}), frozenset()),
    "ionice": (frozenset({"-c", "-n", "--class", "--classdata"}), frozenset()),
    "stdbuf": (frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}), frozenset()),
    "timeout": (frozenset({"-s", "-k", "--signal", "--kill-after"}), frozenset()),
    "time": (frozenset({"-o", "--output", "-f", "--format"}), frozenset()),
    "caffeinate": (frozenset({"-t", "-w"}), frozenset()),
    "exec": (frozenset({"-a"}), frozenset()),
    "nohup": (frozenset(), frozenset()),
    "builtin": (frozenset(), frozenset()),
    "command": (frozenset(), frozenset()),
    "nocorrect": (frozenset(), frozenset()),
    "noglob": (frozenset(), frozenset()),
    "setsid": (frozenset(), frozenset()),
    "chronic": (frozenset(), frozenset()),
    "unbuffer": (frozenset(), frozenset()),
}
_MUTATOR_VALUED: dict[str, frozenset[str]] = {
    "tee": frozenset({"--output-error"}),
    "cp": frozenset({"-t", "--target-directory", "-S", "--suffix"}),
    "mv": frozenset({"-t", "--target-directory", "-S", "--suffix"}),
    "install": frozenset(
        {"-t", "--target-directory", "-m", "--mode", "-o", "--owner", "-g", "--group", "-S"}
    ),
    "ln": frozenset({"-t", "--target-directory", "-S", "--suffix"}),
    "rsync": frozenset(
        {
            "-e",
            "--rsh",
            "-f",
            "--filter",
            "-T",
            "--temp-dir",
            "-B",
            "--exclude",
            "--include",
            "--exclude-from",
            "--include-from",
            "--files-from",
            "--log-file",
            "--backup-dir",
            "--partial-dir",
            "--password-file",
            "--chmod",
            "--chown",
            "--compare-dest",
            "--copy-dest",
            "--link-dest",
            "--suffix",
            "--out-format",
            "-M",
            "--remote-option",
            "--port",
            "--timeout",
            "--bwlimit",
            "--max-size",
            "--min-size",
            "--info",
            "--debug",
        }
    ),  # fmt: skip
    "rm": frozenset(),
    "rmdir": frozenset(),
    "unlink": frozenset(),
    "shred": frozenset({"-n", "--iterations", "-s", "--size", "--random-source"}),
    "srm": frozenset(),
    "truncate": frozenset({"-s", "--size", "-r", "--reference"}),
    "touch": frozenset({"-r", "--reference", "-d", "--date", "-t", "-A"}),
    "chmod": frozenset({"--reference"}),
    "chown": frozenset({"--reference", "--from"}),
    "chgrp": frozenset({"--reference"}),
    "chflags": frozenset(),
    "chattr": frozenset({"-v", "-p"}),
    "setfacl": frozenset({"-m", "-x", "-M", "-X", "--modify", "--remove", "--set"}),
    "xattr": frozenset(),
    "mkdir": frozenset({"-m", "--mode"}),
    "mkfifo": frozenset({"-m", "--mode"}),
    "mknod": frozenset({"-m", "--mode"}),
}
_REMOVERS = frozenset(
    {"rm", "rmdir", "unlink", "shred", "srm", "chmod", "chown", "chgrp", "chflags", "chattr"}
    | {"setfacl", "xattr"}
)
_CREATORS = frozenset({"tee", "truncate", "touch", "mkdir", "mkfifo", "mknod"})
_COPIERS = frozenset({"cp", "mv", "install", "ln", "rsync"})
_GIT_PATHS = frozenset({"rm", "mv", "restore", "checkout", "checkout-index", "clean"})
# curl/wget: short options that take a value, and the options that name an output file.
_CURL_SHORT_VALUED = frozenset("AbcCdDeEFHKmoPQrTuUwxXyYz")
_WGET_SHORT_VALUED = frozenset("OoaPeiBtTwQUlDIXRA")
_CURL_OUTPUT_LONG = frozenset(
    {
        "--output", "--dump-header", "--cookie-jar", "--trace", "--trace-ascii", "--stderr",
        "--etag-save", "--libcurl", "--hsts", "--alt-svc",
    }
)  # fmt: skip
_WGET_OUTPUT_LONG = frozenset(
    {"--output-document", "--output-file", "--append-output", "--save-cookies", "--warc-file"}
)
_HTTP_VALUED_LONG = (
    _CURL_OUTPUT_LONG
    | _WGET_OUTPUT_LONG
    | frozenset(
        {
            "--output-dir", "--directory-prefix", "--url", "--header", "--data", "--data-raw",
            "--data-binary", "--data-urlencode", "--json", "--user", "--request", "--config",
            "--cookie", "--form", "--user-agent", "--referer", "--proxy", "--max-time",
            "--connect-timeout", "--retry", "--cert", "--key", "--cacert", "--capath",
            "--upload-file", "--write-out", "--range", "--resolve", "--connect-to",
            "--oauth2-bearer", "--aws-sigv4", "--tries", "--timeout", "--wait", "--level",
            "--accept", "--reject", "--domains", "--input-file", "--post-data", "--post-file",
            "--body-data", "--method", "--http-user", "--http-password", "--password",
            "--load-cookies", "--ca-certificate", "--certificate", "--private-key",
        }
    )
)  # fmt: skip


class ParseError(Exception):
    """Shell text this module cannot split with certainty."""


@dataclass(frozen=True)
class ScanContext:
    """I/O the scanner may use, bound by the guard to one project.

    ``protected(path, cwd, ancestors)`` -> bool, or None when unresolvable;
    ``read_text(path, cwd)`` -> script text inside the project, or None;
    ``is_dir(path, cwd)`` -> True for an existing directory.
    """

    protected: Callable[[str, str | None, bool], bool | None]
    read_text: Callable[[str, str | None], str | None]
    is_dir: Callable[[str, str | None], bool]


# --------------------------------------------------------------------------- lexer


@dataclass
class Word:
    text: str
    raw: str
    literal: bool
    subs: list[str] = field(default_factory=list)


@dataclass
class Redir:
    op: str
    target: Word | None = None
    delim: str = ""
    body: str | None = None
    body_literal: bool = True


@dataclass
class Cmd:
    words: list[Word] = field(default_factory=list)
    redirs: list[Redir] = field(default_factory=list)
    procsubs: list[str] = field(default_factory=list)
    group: str | None = None
    sep: str = ""


def _skip_single(s: str, j: int) -> int:
    end = s.find("'", j + 1)
    if end < 0:
        raise ParseError("unterminated single quote")
    return end + 1


def _skip_double(s: str, j: int) -> int:
    j += 1
    while j < len(s):
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if c == '"':
            return j + 1
        if c == "$" and s.startswith("$(", j):
            j = _match_close(s, j + 2, "(", ")") + 1
            continue
        if c == "`":
            j = _skip_backtick(s, j)
            continue
        j += 1
    raise ParseError("unterminated double quote")


def _skip_backtick(s: str, j: int) -> int:
    j += 1
    while j < len(s):
        if s[j] == "\\":
            j += 2
            continue
        if s[j] == "`":
            return j + 1
        j += 1
    raise ParseError("unterminated backtick")


def _match_close(s: str, j: int, open_ch: str, close_ch: str) -> int:
    """Index of the bracket closing the one just before ``j``."""
    depth = 1
    while j < len(s):
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if c == "'":
            j = _skip_single(s, j)
            continue
        if c == '"':
            j = _skip_double(s, j)
            continue
        if c == "`":
            j = _skip_backtick(s, j)
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return j
        j += 1
    raise ParseError("unbalanced brackets")


def _extract_subs(text: str) -> list[str]:
    """Command substitutions inside text that the shell expands (unquoted here-doc body)."""
    subs: list[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if text.startswith("$(", i):
            j = _match_close(text, i + 2, "(", ")")
            subs.append(text[i + 2 : j])
            i = j + 1
            continue
        if text.startswith("${", i):
            j = _match_close(text, i + 2, "{", "}")
            subs.extend(_extract_subs(text[i + 2 : j]))
            i = j + 1
            continue
        if c == "`":
            j = _skip_backtick(text, i)
            subs.append(text[i + 1 : j - 1].replace("\\`", "`"))
            i = j
            continue
        i += 1
    return subs


class _Lexer:
    def __init__(self, s: str) -> None:
        self.s = s
        self.n = len(s)
        self.i = 0
        self.cmds: list[Cmd] = []
        self.cur = Cmd()
        self.pending: Redir | None = None
        self.heredocs: list[Redir] = []
        self._reset()

    def _reset(self) -> None:
        self.buf: list[str] = []
        self.start = -1
        self.literal = True
        self.quoted = False
        self.brace = False
        self.subs: list[str] = []

    def _begin(self) -> None:
        if self.start < 0:
            self.start = self.i

    def _flush(self) -> None:
        if self.start < 0:
            return
        raw = self.s[self.start : self.i]
        text = "".join(self.buf)
        literal = self.literal and not (self.brace and raw not in ("{", "}"))
        word = Word(text, raw, literal, self.subs)
        self._reset()
        if self.pending is None:
            self.cur.words.append(word)
            return
        redir, self.pending = self.pending, None
        if redir.op in _HEREDOC_OPS:
            redir.delim = text
            redir.body_literal = any(ch in raw for ch in "'\"\\")
            self.heredocs.append(redir)
        elif redir.op == "<<<":
            redir.target = word
            redir.body = text
            redir.body_literal = word.literal
        else:
            redir.target = word
        self.cur.redirs.append(redir)

    def _end(self, sep: str) -> None:
        self._flush()
        if self.pending is not None:
            raise ParseError("redirection without a target")
        cur = self.cur
        if cur.words or cur.redirs or cur.group is not None or cur.procsubs:
            cur.sep = sep
            self.cmds.append(cur)
        elif sep in ("&&", "||", "|", "|&"):
            raise ParseError("operator without a command")
        self.cur = Cmd()

    def _heredoc_bodies(self) -> None:
        for redir in self.heredocs:
            lines: list[str] = []
            while self.i < self.n:
                j = self.s.find("\n", self.i)
                line = self.s[self.i : self.n if j < 0 else j]
                self.i = self.n if j < 0 else j + 1
                if redir.op == "<<-":
                    line = line.lstrip("\t")
                if line == redir.delim:
                    break
                lines.append(line)
            redir.body = "\n".join(lines)
        self.heredocs = []

    def _dollar(self, in_dq: bool) -> None:
        s, i = self.s, self.i
        nx = s[i + 1] if i + 1 < self.n else ""
        if nx == "(":
            j = _match_close(s, i + 2, "(", ")")
            inner = s[i + 2 : j]
            arithmetic = inner.startswith("(") and inner.endswith(")")
            if not arithmetic or "$(" in inner or "`" in inner:
                self.subs.append(inner[1:-1] if arithmetic else inner)
            self.buf.append(s[i : j + 1])
            self.literal = False
            self.i = j + 1
            return
        if nx == "{":
            j = _match_close(s, i + 2, "{", "}")
            self.subs.extend(_extract_subs(s[i + 2 : j]))
            self.buf.append(s[i : j + 1])
            self.literal = False
            self.i = j + 1
            return
        if nx == "'" and not in_dq:
            j = i + 2
            while j < self.n and s[j] != "'":
                j += 2 if s[j] == "\\" else 1
            if j >= self.n:
                raise ParseError("unterminated $'")
            self.buf.append(s[i + 2 : j])
            self.literal = False
            self.quoted = True
            self.i = j + 1
            return
        if nx == '"' and not in_dq:
            self.i += 1
            self._dquote()
            self.literal = False
            return
        if nx and (nx.isalnum() or nx in "_@*#?$!-"):
            j = i + 2
            if nx.isalpha() or nx == "_":
                while j < self.n and (s[j].isalnum() or s[j] == "_"):
                    j += 1
            self.buf.append(s[i:j])
            self.literal = False
            self.i = j
            return
        self.buf.append("$")
        self.i += 1

    def _backtick(self) -> None:
        j = _skip_backtick(self.s, self.i)
        self.subs.append(self.s[self.i + 1 : j - 1].replace("\\`", "`"))
        self.buf.append(self.s[self.i : j])
        self.literal = False
        self.i = j

    def _dquote(self) -> None:
        s = self.s
        self.quoted = True
        self.i += 1
        while True:
            if self.i >= self.n:
                raise ParseError("unterminated double quote")
            d = s[self.i]
            if d == '"':
                self.i += 1
                return
            if d == "\\" and self.i + 1 < self.n and s[self.i + 1] in '"\\$`\n':
                if s[self.i + 1] != "\n":
                    self.buf.append(s[self.i + 1])
                self.i += 2
                continue
            if d == "$":
                self._dollar(in_dq=True)
                continue
            if d == "`":
                self._backtick()
                continue
            self.buf.append(d)
            self.i += 1

    def run(self) -> list[Cmd]:
        s = self.s
        while self.i < self.n:
            c = s[self.i]
            if c in " \t\r":
                self._flush()
                self.i += 1
                continue
            if c == "\n":
                self._flush()
                self.i += 1
                if self.heredocs:
                    self._heredoc_bodies()
                self._end("\n")
                continue
            if c == "#" and self.start < 0:
                j = s.find("\n", self.i)
                self.i = self.n if j < 0 else j
                continue
            if c in "<>" and self.i + 1 < self.n and s[self.i + 1] == "(":
                self._flush()
                j = _match_close(s, self.i + 2, "(", ")")
                self.cur.procsubs.append(s[self.i + 2 : j])
                self.cur.words.append(Word(s[self.i : j + 1], s[self.i : j + 1], False))
                self.i = j + 1
                continue
            if c in "<>" or (c == "&" and s.startswith("&>", self.i)):
                digits = "".join(self.buf)
                is_fd = (
                    self.start >= 0
                    and digits.isdigit()
                    and self.literal
                    and not self.quoted
                    and s[self.start : self.i] == digits
                )
                if is_fd:
                    self._reset()
                else:
                    self._flush()
                if self.pending is not None:
                    raise ParseError("redirection without a target")
                op = next(o for o in _REDIR_OPS if s.startswith(o, self.i))
                self.pending = Redir(op)
                self.i += len(op)
                continue
            if c in "|&;":
                self._flush()
                op = next(o for o in _SEP_OPS if s.startswith(o, self.i))
                self._end(op)
                self.i += len(op)
                continue
            if c == "(":
                self._flush()
                j = _match_close(s, self.i + 1, "(", ")")
                inner = s[self.i + 1 : j]
                self.i = j + 1
                if self.cur.words:
                    if inner.strip():
                        raise ParseError("unexpected parenthesis")
                    continue  # name() function definition header
                if self.cur.group is not None:
                    raise ParseError("two groups in one command")
                self.cur.group = inner
                continue
            if c == ")":
                raise ParseError("unmatched parenthesis")
            self._begin()
            if c == "\\":
                if self.i + 1 >= self.n:
                    raise ParseError("trailing backslash")
                if s[self.i + 1] == "\n":
                    self.i += 2
                    if not self.buf and not self.quoted:
                        self.start = -1
                    continue
                self.buf.append(s[self.i + 1])
                self.quoted = True
                self.i += 2
                continue
            if c == "'":
                j = _skip_single(s, self.i)
                self.buf.append(s[self.i + 1 : j - 1])
                self.quoted = True
                self.i = j
                continue
            if c == '"':
                self._dquote()
                continue
            if c == "$":
                self._dollar(in_dq=False)
                continue
            if c == "`":
                self._backtick()
                continue
            if c in "*?[":
                self.literal = False
            elif c in "{}":
                self.brace = True
            elif c == "~" and not self.buf and not self.quoted:
                self.literal = False
            self.buf.append(c)
            self.i += 1
        self._flush()
        if self.pending is not None:
            raise ParseError("redirection without a target")
        for redir in self.heredocs:
            redir.body = ""
        self._end("")
        return self.cmds


def parse(text: str) -> list[Cmd]:
    if not isinstance(text, str):
        raise ParseError("not text")
    try:
        return _Lexer(text).run()
    except RecursionError:
        raise ParseError("too deep") from None


# --------------------------------------------------------------------------- text rules


def approval_text(text: str) -> bool:
    """``cab``/``cab_of_one`` followed on one line by a human-only verb."""
    for line in text.replace("\r", "\n").split("\n"):
        for match in _CAB_WORD.finditer(line):
            rest = line[match.end() :]
            if _APPROVAL_VERB.search(rest) or _SETUP_VERB.search(rest):
                return True
    return False


def intake_text(text: str) -> bool:
    """``cab``/``cab_of_one`` followed on one line by the word ``intake``.

    Interactive ``cab intake CHG-NNNN`` is a person's terminal command. The only agent
    form, the exact literal fixture call of the pinned CLI (``... intake CHG-NNNN
    --from-file FILE``), is allowed by guard step 1a before this scan runs, so every
    ``cab ... intake`` text that reaches the scan is refused, ``--from-file`` or not:
    a wrapper, a nested shell or a pseudo-terminal can turn either form into a terminal
    session the guard cannot see into."""
    for line in text.replace("\r", "\n").split("\n"):
        for match in _CAB_WORD.finditer(line):
            if _INTAKE_VERB.search(line[match.end() :]):
                return True
    return False


def _authority(text: str) -> bool:
    if approval_text(text) or intake_text(text):
        return True
    return bool(_PTY_WORD.search(text) and _CAB_WORD.search(text))


def _unknown_word() -> Word:
    return Word("{xargs}", "{xargs}", False)


def _base(word: Word) -> str:
    return posixpath.basename(word.text).lower()


# --------------------------------------------------------------------------- scanner


class _Scanner:
    def __init__(self, ctx: ScanContext, strict: bool) -> None:
        self.ctx = ctx
        self.strict = strict  # any file write (not only protected) is refused

    # -- texts

    def text(self, text: str, cwd: str | None, depth: int) -> str | None:
        if depth > MAX_DEPTH or len(text) > MAX_TEXT:
            return OPAQUE_WRITE
        if _authority(text):
            return APPROVAL
        try:
            cmds = parse(text)
        except ParseError:
            if self.strict or _FRAGMENTS.search(text) or _COMPONENTS.search(text):
                return OPAQUE_WRITE
            return None
        current = cwd
        prev = ""
        for cmd in cmds:
            piped = cmd.sep in ("|", "|&", "&") or prev in ("|", "|&", "&")
            code, current = self._cmd(cmd, current, depth, piped, text)
            if code:
                return code
            prev = cmd.sep
        return None

    def _code_text(self, text: str) -> str | None:
        if _authority(text):
            return APPROVAL
        if _FRAGMENTS.search(text):
            return OPAQUE_SCRIPT
        return None

    # -- one simple command

    def _cmd(
        self, cmd: Cmd, cwd: str | None, depth: int, piped: bool, raw: str
    ) -> tuple[str | None, str | None]:
        words = list(cmd.words) + [r.target for r in cmd.redirs if r.target is not None]
        for word in words:
            for sub in word.subs:
                code = self.text(sub, cwd, depth + 1)
                if code:
                    return code, cwd
        for sub in cmd.procsubs:
            code = self.text(sub, cwd, depth + 1)
            if code:
                return code, cwd
        stdin_code = None
        for redir in cmd.redirs:
            code = self._redir(redir, cwd, depth)
            if code:
                return code, cwd
            if redir.op in _HEREDOC_OPS or redir.op == "<<<":
                stdin_code = redir.body or ""
        if cmd.group is not None:
            return self.text(cmd.group, cwd, depth + 1), cwd
        argv = list(cmd.words)
        while argv and _ASSIGN.match(argv[0].raw):
            argv.pop(0)
        while argv and argv[0].literal and argv[0].text in _KEYWORDS_SKIP:
            argv.pop(0)
        if not argv or (argv[0].literal and argv[0].text in _KEYWORDS_STOP):
            return None, cwd
        return self._argv(argv, cwd, depth, piped, stdin_code, raw)

    def _redir(self, redir: Redir, cwd: str | None, depth: int) -> str | None:
        op = redir.op
        if op in _HEREDOC_OPS:
            if redir.body and not redir.body_literal:
                try:
                    subs = _extract_subs(redir.body)
                except ParseError:
                    return OPAQUE_WRITE
                for sub in subs:
                    code = self.text(sub, cwd, depth + 1)
                    if code:
                        return code
            return None
        if op in ("<", "<&", "<<<"):
            return None
        if op == ">&":
            t = redir.target
            if t is not None and t.literal and (t.text.isdigit() or t.text == "-"):
                return None
        return self._target(redir.target, cwd, "write")

    def _target(self, word: Word | None, cwd: str | None, kind: str) -> str | None:
        if word is None or not word.literal or word.subs or not word.text:
            return OPAQUE_WRITE
        path = word.text
        if path in _SINKS or path.startswith("/dev/fd/"):
            return None
        if not path.startswith("/") and cwd is None:
            return OPAQUE_WRITE
        hit = self.ctx.protected(path, cwd, kind == "remove")
        if hit is None:
            return OPAQUE_WRITE
        if hit:
            return PROTECTED
        return OPAQUE_WRITE if self.strict else None

    def _generic(self, args: Sequence[Word], cwd: str | None) -> str | None:
        for word in args:
            if not word.literal or word.subs:
                continue
            text = word.text
            if text.startswith("-"):
                if "=" not in text:
                    continue
                text = text.split("=", 1)[1]
            if not text or text in _SINKS:
                continue
            if not text.startswith("/") and cwd is None:
                if _COMPONENTS.search(text) or _FRAGMENTS.search(text):
                    return PROTECTED
                continue
            if self.ctx.protected(text, cwd, False):
                return PROTECTED
        return None

    # -- dispatch

    def _argv(
        self,
        argv: list[Word],
        cwd: str | None,
        depth: int,
        piped: bool,
        stdin_code: str | None,
        raw: str,
    ) -> tuple[str | None, str | None]:
        if depth > MAX_DEPTH:
            return OPAQUE_WRITE, cwd
        joined = " ".join(w.text for w in argv)
        if approval_text(joined) or intake_text(joined):
            return APPROVAL, cwd
        head, args = argv[0], argv[1:]
        if not head.literal:
            return self._generic(args, cwd), cwd
        name = _base(head)
        if name in ("cd", "pushd", "popd", "chdir"):
            return None, self._cd(name, args, cwd, piped)
        if name in _WRAPPERS:
            return self._wrapper(name, args, cwd, depth, piped, stdin_code, raw)
        if name in ("script", "socat", "tmux", "screen"):
            return self._pty(name, args, cwd, depth, piped, raw), cwd
        if name == "xargs":
            return self._xargs(args, cwd, depth, piped, raw), cwd
        if name == "find":
            return self._find(args, cwd, depth, piped, raw), cwd
        if name in _SHELLS:
            return self._shell(args, cwd, depth, stdin_code, raw), cwd
        if _PYTHON.match(name) or name in _INTERPRETERS:
            return self._interp(name, args, cwd, stdin_code, raw), cwd
        if name == "eval":
            if all(w.literal and not w.subs for w in args):
                return self.text(" ".join(w.text for w in args), cwd, depth + 1), cwd
            hit = _FRAGMENTS.search(raw) or _COMPONENTS.search(raw)
            return (OPAQUE_WRITE if hit or self.strict else None), cwd
        if name == "trap":
            return self._trap(args, cwd, depth, raw), cwd
        if name in ("source", "."):
            return self._source(args, cwd, depth), None
        if name in _MUTATOR_VALUED:
            return self._mutate(name, args, cwd), cwd
        if name == "dd":
            for word in args:
                if word.text.startswith("of="):
                    code = self._target(
                        Word(word.text[3:], word.raw, word.literal, word.subs), cwd, "write"
                    )
                    if code:
                        return code, cwd
            return None, cwd
        if name == "sed":
            return self._sed(args, cwd), cwd
        if name in ("curl", "wget"):
            return (self._http(name, args, cwd) or self._generic(args, cwd)), cwd
        if name == "git":
            return self._git(args, cwd), cwd
        if name in _READ_ONLY:
            return self._read_only(name, args, cwd), cwd
        return self._generic(args, cwd), cwd

    def _cd(self, name: str, args: Sequence[Word], cwd: str | None, piped: bool) -> str | None:
        if name != "cd" or piped or cwd is None:
            return None
        operands = [w for w in args if not (w.literal and w.text in ("-P", "-L", "-e", "-@"))]
        if len(operands) != 1:
            return None
        word = operands[0]
        if not word.literal or word.subs or not word.text or word.text == "-":
            return None
        return os.path.normpath(os.path.join(cwd, word.text))

    def _wrapper(
        self,
        name: str,
        args: list[Word],
        cwd: str | None,
        depth: int,
        piped: bool,
        stdin_code: str | None,
        raw: str,
    ) -> tuple[str | None, str | None]:
        valued, chdir = _WRAPPERS[name]
        i = 0
        cwd_unknown = False
        while i < len(args):
            word = args[i]
            text = word.text
            if not word.literal:
                break
            if text == "--":
                i += 1
                break
            if name == "env" and (_ASSIGN.match(word.raw) or text == "-"):
                i += 1
                continue
            if not text.startswith("-") or text == "-":
                break
            opt, eq, inline = text.partition("=")
            if name == "env" and (opt in ("-S", "--split-string") or opt.startswith("-S")):
                if eq:
                    split = inline
                elif len(opt) > 2 and not opt.startswith("--"):
                    split = opt[2:]
                else:
                    split = args[i + 1].text if i + 1 < len(args) else ""
                    if i + 1 < len(args) and not args[i + 1].literal:
                        return OPAQUE_WRITE, cwd
                return self.text(split, cwd, depth + 1), cwd
            if opt in chdir or (opt[:2] in chdir and not opt.startswith("--")):
                cwd_unknown = True
            if opt in valued or opt in chdir:
                if name == "time" and opt in ("-o", "--output"):
                    value = Word(inline, inline, word.literal) if eq else None
                    if value is None and i + 1 < len(args):
                        value = args[i + 1]
                    code = self._target(value, cwd, "write")
                    if code:
                        return code, cwd
                i += 1 if eq else 2
                continue
            i += 1
        rest = args[i:]
        if name == "timeout" and rest:
            rest = rest[1:]
        if not rest:
            return None, cwd
        inner_cwd = None if cwd_unknown else cwd
        code, _ = self._argv(rest, inner_cwd, depth + 1, piped, stdin_code, raw)
        moved = rest[0].literal and _base(rest[0]) in ("cd", "pushd", "popd")
        return code, (None if moved else cwd)

    def _pty(
        self, name: str, args: list[Word], cwd: str | None, depth: int, piped: bool, raw: str
    ) -> str | None:
        if name == "script":
            i = 0
            while i < len(args):
                word = args[i]
                text = word.text
                if not word.literal:
                    return OPAQUE_WRITE
                if text == "--":
                    i += 1
                    break
                if not text.startswith("-") or text == "-":
                    break
                opt, eq, inline = text.partition("=")
                if opt in ("-c", "--command"):
                    if not eq and i + 1 < len(args) and not args[i + 1].literal:
                        return OPAQUE_WRITE
                    value = inline if eq else (args[i + 1].text if i + 1 < len(args) else "")
                    code = self.text(value, cwd, depth + 1)
                    if code:
                        return code
                    i += 1 if eq else 2
                    continue
                if opt in ("-T", "--log-timing", "-O", "--log-out", "-I", "--log-in", "-B"):
                    target = Word(inline, inline, True) if eq else None
                    if target is None and i + 1 < len(args):
                        target = args[i + 1]
                    code = self._target(target, cwd, "write")
                    if code:
                        return code
                    i += 1 if eq else 2
                    continue
                if opt in ("-t", "-m", "--logging-format", "-E", "--echo"):
                    i += 1 if eq else 2
                    continue
                i += 1
            rest = args[i:]
            if not rest:
                return None
            code = self._target(rest[0], cwd, "write")  # the typescript file
            if code or len(rest) == 1:
                return code
            code, _ = self._argv(rest[1:], cwd, depth + 1, piped, None, raw)
            return code
        for word in args:
            text = word.text
            if not word.literal:
                if _FRAGMENTS.search(text) or self.strict:
                    return OPAQUE_WRITE
                continue
            if name == "socat":
                kind, _, rest = text.partition(":")
                if kind.lower() in ("exec", "system"):
                    code = self.text(rest.split(",", 1)[0], cwd, depth + 1)
                    if code:
                        return code
                    continue
                if kind.lower() in ("create", "open", "gopen"):
                    path = rest.split(",", 1)[0]
                    code = self._target(Word(path, path, True), cwd, "write")
                    if code:
                        return code
                    continue
            if any(ch.isspace() for ch in text):  # tmux/screen: a shell command string
                code = self.text(text, cwd, depth + 1)
                if code:
                    return code
        return None

    def _xargs(
        self, args: list[Word], cwd: str | None, depth: int, piped: bool, raw: str
    ) -> str | None:
        valued = {
            "-I", "-L", "-n", "-P", "-s", "-d", "-E", "-a", "--arg-file", "--delimiter",
            "--max-args", "--max-lines", "--max-procs", "--max-chars", "--eof", "--replace",
            "--process-slot-var",
        }  # fmt: skip
        i = 0
        while i < len(args):
            word = args[i]
            text = word.text
            if text == "--" and word.literal:
                i += 1
                break
            if not text.startswith("-"):
                break  # the command (a non-literal option such as -I{} is still an option)
            opt, eq, _ = text.partition("=")
            i += 1 if (eq or opt not in valued) else 2
        rest = args[i:]
        if not rest:
            return None
        code, _ = self._argv([*rest, _unknown_word()], cwd, depth + 1, piped, None, raw)
        return code

    def _find(
        self, args: list[Word], cwd: str | None, depth: int, piped: bool, raw: str
    ) -> str | None:
        i = 0
        options = ("-H", "-L", "-P", "-E", "-X", "-s", "-x", "-d", "-O0", "-O1", "-O2", "-O3")
        while i < len(args) and args[i].literal and args[i].text in options:
            i += 1
        starts: list[Word] = []
        while i < len(args):
            word = args[i]
            if word.literal and (word.text.startswith("-") or word.text in ("(", "!", ")")):
                break
            starts.append(word)
            i += 1
        if not starts:
            starts = [Word(".", ".", True)]
        expr = args[i:]
        j = 0
        while j < len(expr):
            text = expr[j].text if expr[j].literal else ""
            if text == "-delete":
                for start in starts:
                    code = self._target(start, cwd, "remove")
                    if code:
                        return code
            elif text in ("-exec", "-execdir", "-ok", "-okdir"):
                k = j + 1
                sub: list[Word] = []
                while k < len(expr) and not (expr[k].literal and expr[k].text in (";", "+")):
                    word = expr[k]
                    sub.append(Word(word.text, word.raw, False) if "{}" in word.text else word)
                    k += 1
                if sub:
                    inner_cwd = cwd if text in ("-exec", "-ok") else None
                    code, _ = self._argv(sub, inner_cwd, depth + 1, piped, None, raw)
                    if code:
                        return code
                j = k
            elif text in ("-fprint", "-fprint0", "-fls", "-fprintf"):
                code = self._target(expr[j + 1] if j + 1 < len(expr) else None, cwd, "write")
                if code:
                    return code
                j += 1
            j += 1
        return None

    def _shell(
        self, args: list[Word], cwd: str | None, depth: int, stdin_code: str | None, raw: str
    ) -> str | None:
        i = 0
        from_stdin = False
        while i < len(args):
            word = args[i]
            text = word.text
            if not word.literal:
                return OPAQUE_SCRIPT
            if text == "--":
                i += 1
                break
            if text.startswith("--"):
                i += 1
                continue
            if text.startswith(("-", "+")) and len(text) > 1:
                letters = text[1:]
                if text.startswith("-") and "c" in letters:
                    if i + 1 >= len(args) or not args[i + 1].literal:
                        return OPAQUE_SCRIPT
                    return self.text(args[i + 1].text, cwd, depth + 1)
                if letters in ("o", "O"):
                    i += 2
                    continue
                if "s" in letters:
                    from_stdin = True
                i += 1
                continue
            break
        if i < len(args) and not from_stdin:
            script = args[i]
            if not script.literal:
                return OPAQUE_SCRIPT
            text = self.ctx.read_text(script.text, cwd)
            if text is None:
                return OPAQUE_SCRIPT
            code = self.text(text, cwd, depth + 1)
            return code or self._generic(args[i + 1 :], cwd)
        if stdin_code is not None:
            return self.text(stdin_code, cwd, depth + 1)
        return OPAQUE_SCRIPT if (_FRAGMENTS.search(raw) or self.strict) else None

    def _trap(self, args: list[Word], cwd: str | None, depth: int, raw: str) -> str | None:
        """``trap ACTION SIGNAL...`` runs ACTION later in this shell: scan it as shell text."""
        operands = [w for w in args if not (w.literal and w.text in ("-l", "-p", "--"))]
        if len(operands) < 2:
            return None  # listing, or resetting a signal (no callback)
        action = operands[0]
        if not action.literal or action.subs:
            hit = _FRAGMENTS.search(raw) or _COMPONENTS.search(raw)
            return OPAQUE_WRITE if hit or self.strict else None
        if action.text in ("", "-"):
            return None
        return self.text(action.text, cwd, depth + 1)

    def _source(self, args: list[Word], cwd: str | None, depth: int) -> str | None:
        if not args:
            return None
        script = args[0]
        if not script.literal:
            return OPAQUE_SCRIPT
        text = self.ctx.read_text(script.text, cwd)
        if text is None:
            return OPAQUE_SCRIPT
        return self.text(text, cwd, depth + 1)

    def _interp(
        self, name: str, args: list[Word], cwd: str | None, stdin_code: str | None, raw: str
    ) -> str | None:
        pwsh = name in ("pwsh", "powershell")
        awk = name in ("awk", "gawk", "mawk", "nawk")
        perlish = name in ("perl", "ruby")
        if _PYTHON.match(name):
            code_opts, file_opts, valued = {"-c"}, set(), {"-W", "-X", "-Q"}
        elif name in ("node", "nodejs", "bun"):
            code_opts = {"-e", "--eval", "-p", "--print"}
            file_opts, valued = set(), {"-r", "--require", "--import", "--loader"}
        elif pwsh:
            code_opts, file_opts = {"-command", "-c"}, {"-file", "-f"}
            valued = {
                "-executionpolicy", "-ex", "-ep", "-configurationname", "-settingsfile",
                "-version", "-v", "-outputformat", "-of", "-inputformat", "-if",
                "-windowstyle", "-w", "-workingdirectory", "-wd",
            }  # fmt: skip
        elif awk:
            code_opts, file_opts, valued = set(), {"-f"}, {"-v", "-F"}
        elif name == "expect":
            code_opts, file_opts, valued = {"-c"}, {"-f"}, set()
        elif name == "php":
            code_opts, file_opts, valued = {"-r"}, {"-f"}, {"-d", "-c", "-z"}
        else:
            code_opts, file_opts = {"-e", "-E"}, set()
            valued = {"-I", "-M", "-m", "-r", "-C", "-l", "-s"}
        codes: list[str] = []
        scripts: list[Word] = []
        program_given = False
        inplace = False
        i = 0
        while i < len(args):
            word = args[i]
            text = word.text
            key = text.lower() if pwsh else text
            if not word.literal:
                if text.startswith("-"):
                    return OPAQUE_SCRIPT
                break
            if text == "--":
                i += 1
                break
            if not text.startswith("-") or text == "-":
                break
            opt, eq, inline = key.partition("=")
            if pwsh and opt in ("-encodedcommand", "-enc", "-e", "-ec"):
                return OPAQUE_SCRIPT
            if pwsh and opt in ("-workingdirectory", "-wd"):
                cwd = None
            if awk and opt in ("-i", "--include"):
                value = inline if eq else (args[i + 1].text if i + 1 < len(args) else "")
                if value == "inplace":
                    inplace = True  # gawk -i inplace edits its input files
                i += 1 if eq else 2
                continue
            if perlish and not text.startswith("--"):
                letters = text[1:]
                if "i" in letters.split("e")[0].split("E")[0]:
                    inplace = True
                if letters and letters[-1] in "eE" and "i" not in letters[-1:]:
                    if i + 1 >= len(args) or not args[i + 1].literal:
                        return OPAQUE_SCRIPT
                    codes.append(args[i + 1].text)
                    program_given = True
                    i += 2
                    continue
            if opt in code_opts:
                if pwsh:
                    rest = args[i + 1 :]
                    if any(not w.literal for w in rest):
                        return OPAQUE_SCRIPT
                    codes.append(" ".join(w.text for w in rest))
                    program_given = True
                    i = len(args)
                    break
                value = inline if eq else (args[i + 1].text if i + 1 < len(args) else None)
                if value is None or (not eq and not args[i + 1].literal):
                    return OPAQUE_SCRIPT
                codes.append(value)
                program_given = True
                i += 1 if eq else 2
                continue
            if opt in file_opts:
                if i + 1 >= len(args):
                    return OPAQUE_SCRIPT
                scripts.append(args[i + 1])
                program_given = True
                i += 2
                continue
            if _PYTHON.match(name) and opt == "-m":
                program_given = True
                i = len(args) if i + 1 >= len(args) else i + 2
                break
            if opt in valued:
                i += 1 if eq else 2
                continue
            i += 1
        rest = args[i:]
        if not program_given and rest:
            first, rest = rest[0], rest[1:]
            if name in ("npx", "uv", "uvx", "deno"):
                program_given = True  # package runners: the program is not a local file
            elif awk:
                if not first.literal:
                    return OPAQUE_SCRIPT
                codes.append(first.text)
                program_given = True
            elif first.literal and first.text == "-":
                pass  # program from stdin
            else:
                scripts.append(first)
                program_given = True
        for text in codes:
            code = self._code_text(text)
            if code:
                return code
        for script in scripts:
            if not script.literal:
                return OPAQUE_SCRIPT
            body = self.ctx.read_text(script.text, cwd)
            if body is None:
                return OPAQUE_SCRIPT
            code = self._code_text(body)
            if code:
                return code
        if not program_given:
            if stdin_code is not None:
                code = self._code_text(stdin_code)
                if code:
                    return code
            elif _FRAGMENTS.search(raw) or self.strict:
                return OPAQUE_SCRIPT
        if inplace:
            for word in rest:
                code = self._target(word, cwd, "write")
                if code:
                    return code
        if awk:
            return None  # remaining operands are input files (reads)
        return self._generic(rest, cwd)

    def _operands(
        self, args: list[Word], valued: Collection[str]
    ) -> tuple[list[Word], dict[str, list[Word]], set[str]]:
        operands: list[Word] = []
        values: dict[str, list[Word]] = {}
        flags: set[str] = set()
        ended = False
        i = 0
        while i < len(args):
            word = args[i]
            text = word.text
            if ended or not word.literal or not text.startswith("-") or text == "-":
                operands.append(word)
                i += 1
                continue
            if text == "--":
                ended = True
                i += 1
                continue
            opt, eq, inline = text.partition("=")
            if opt in valued:
                if eq:
                    values.setdefault(opt, []).append(Word(inline, inline, True))
                elif i + 1 < len(args):
                    values.setdefault(opt, []).append(args[i + 1])
                    i += 1
                i += 1
                continue
            if not opt.startswith("--") and len(opt) > 2 and opt[:2] in valued:
                values.setdefault(opt[:2], []).append(Word(opt[2:], opt[2:], True))
                i += 1
                continue
            flags.add(opt)
            if not opt.startswith("--"):
                flags.update(f"-{letter}" for letter in opt[1:])
            i += 1
        return operands, values, flags

    def _check_all(self, words: Sequence[Word], cwd: str | None, kind: str) -> str | None:
        for word in words:
            code = self._target(word, cwd, kind)
            if code:
                return code
        return None

    def _mutate(self, name: str, args: list[Word], cwd: str | None) -> str | None:
        operands, values, flags = self._operands(args, _MUTATOR_VALUED[name])
        if name in _REMOVERS:
            return self._check_all(operands, cwd, "remove")
        if name in _CREATORS:
            return self._check_all(operands, cwd, "write")
        # copiers: cp, mv, install, ln, rsync
        if name == "install" and "-d" in flags:
            return self._check_all(operands, cwd, "write")
        target_dir = values.get("-t") or values.get("--target-directory")
        if target_dir:
            dest, sources = target_dir[-1], operands
        elif operands:
            dest, sources = operands[-1], operands[:-1]
        else:
            return None
        if name == "rsync":
            for key in ("--log-file", "--backup-dir", "--temp-dir", "-T", "--partial-dir"):
                code = self._check_all(values.get(key, []), cwd, "write")
                if code:
                    return code
            remote = dest.literal and ":" in dest.text.split("/", 1)[0]
            if remote:
                return None
        deleting = name == "rsync" and any(f.startswith("--delete") for f in flags)
        kind = "remove" if deleting else "write"
        code = self._target(dest, cwd, kind)
        if code:
            return code
        if name == "mv":
            code = self._check_all(sources, cwd, "remove")
            if code:
                return code
        if name == "ln":
            code = self._check_all(sources, cwd, "write")
            if code:
                return code
        into_dir = bool(target_dir) or dest.text.endswith("/") or self.ctx.is_dir(dest.text, cwd)
        if into_dir:
            for source in sources:
                if not source.literal or source.subs:
                    return OPAQUE_WRITE
                inner = posixpath.join(dest.text, posixpath.basename(source.text.rstrip("/")))
                code = self._target(Word(inner, inner, True), cwd, kind)
                if code:
                    return code
        return None

    def _http(self, name: str, args: list[Word], cwd: str | None) -> str | None:
        """File outputs of curl/wget only: -o/-O (separate or attached), the long forms,
        and the remote-name files (curl -O, wget by default, joined with the output dir)."""
        curl = name == "curl"
        short_valued = _CURL_SHORT_VALUED if curl else _WGET_SHORT_VALUED
        out_short = frozenset("oDc") if curl else frozenset("Ooa")
        out_long = _CURL_OUTPUT_LONG if curl else _WGET_OUTPUT_LONG
        dir_long = "--output-dir" if curl else "--directory-prefix"
        outputs: list[Word | None] = []
        dirs: list[Word | None] = []
        urls: list[Word] = []
        remote = not curl  # wget saves under the remote name unless -O is given
        i = 0
        while i < len(args):
            word = args[i]
            text = word.text
            if not text.startswith("-") or text == "-":
                if "://" in text or not word.literal:
                    urls.append(word)
                i += 1
                continue
            if not word.literal:
                return OPAQUE_WRITE  # an option the shell computes at run time
            nxt = args[i + 1] if i + 1 < len(args) else None
            if text.startswith("--"):
                opt, eq, inline = text.partition("=")
                value = Word(inline, inline, True) if eq else nxt
                step = 1 if eq else 2
                if opt in out_long:
                    outputs.append(value)
                    if opt == "--output-document":
                        remote = False
                elif opt == dir_long:
                    dirs.append(value)
                elif opt == "--url":
                    if value is not None:
                        urls.append(value)
                elif curl and opt in ("--remote-name", "--remote-name-all"):
                    remote, step = True, 1
                elif opt not in _HTTP_VALUED_LONG:
                    step = 1
                i += step
                continue
            letters = text[1:]
            step = 1
            for k, letter in enumerate(letters):
                if curl and letter == "O":
                    remote = True
                    continue
                if letter in short_valued:
                    tail = letters[k + 1 :]
                    value = Word(tail, tail, True) if tail else nxt
                    step = 1 if tail else 2
                    if letter in out_short:
                        outputs.append(value)
                        if not curl and letter == "O":
                            remote = False
                    elif not curl and letter == "P":
                        dirs.append(value)
                    break
            i += step
        for out in outputs:
            if out is not None and out.literal and out.text == "-":
                continue  # standard output
            code = self._target(out, cwd, "write")
            if code:
                return code
        if not remote:
            return None
        for url in urls:
            if not url.literal or url.subs:
                return OPAQUE_WRITE
            location = url.text.split("://", 1)[-1].split("?", 1)[0].split("#", 1)[0]
            base = posixpath.basename(location.partition("/")[2]) or "index.html"
            for folder in dirs or [Word(".", ".", True)]:
                if folder is None or not folder.literal:
                    return OPAQUE_WRITE
                inner = posixpath.join(folder.text, base)
                code = self._target(Word(inner, inner, True), cwd, "write")
                if code:
                    return code
        return None

    def _sed(self, args: list[Word], cwd: str | None) -> str | None:
        inplace = False
        script_given = False
        scripts: list[Word] = []
        script_files: list[Word] = []
        operands: list[Word] = []
        i = 0
        while i < len(args):
            word = args[i]
            text = word.text
            if not word.literal or not text.startswith("-") or text == "-":
                operands.append(word)
                i += 1
                continue
            if text.startswith("--"):
                opt, eq, inline = text.partition("=")
                if opt == "--in-place":
                    inplace = True
                elif opt in ("--expression", "--file"):
                    value = Word(inline, inline, True) if eq else None
                    if value is None and i + 1 < len(args):
                        value = args[i + 1]
                        i += 1
                    script_given = True
                    if value is not None:
                        (scripts if opt == "--expression" else script_files).append(value)
                i += 1
                continue
            letters = text[1:]
            consumed = False
            for k, letter in enumerate(letters):
                if letter in "iI":
                    inplace = True
                    if k == len(letters) - 1 and i + 1 < len(args) and args[i + 1].text == "":
                        i += 1  # BSD: -i '' (empty backup suffix)
                    break
                if letter in "efl":
                    tail = letters[k + 1 :]
                    value = Word(tail, tail, True) if tail else None
                    if value is None and i + 1 < len(args):
                        value = args[i + 1]
                        consumed = True
                    if letter in "ef":
                        script_given = True
                        if value is not None:
                            (scripts if letter == "e" else script_files).append(value)
                    break
            i += 2 if consumed else 1
        if not script_given and operands:
            scripts.append(operands.pop(0))
        for script in scripts:
            if not script.literal:
                if inplace or self.strict:
                    return OPAQUE_WRITE
                continue
            if _FRAGMENTS.search(script.text):
                return OPAQUE_SCRIPT
        for script_file in script_files:  # sed scripts can write files ("w FILE")
            body = self.ctx.read_text(script_file.text, cwd) if script_file.literal else None
            if body is None or _FRAGMENTS.search(body):
                return OPAQUE_SCRIPT
        if inplace:
            return self._check_all(operands, cwd, "write")
        return None

    def _git(self, args: list[Word], cwd: str | None) -> str | None:
        gcwd = cwd
        i = 0
        while i < len(args):
            word = args[i]
            text = word.text
            if not word.literal:
                return None
            if text == "-C":
                nxt = args[i + 1] if i + 1 < len(args) else None
                if nxt is None or not nxt.literal or gcwd is None:
                    gcwd = None
                else:
                    gcwd = os.path.normpath(os.path.join(gcwd, nxt.text))
                i += 2
                continue
            if text in ("-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"):
                if text == "--work-tree":
                    gcwd = None
                i += 2
                continue
            if text.startswith("--work-tree="):
                gcwd = None
            if text.startswith("-"):
                i += 1
                continue
            break
        if i >= len(args):
            return None
        sub = args[i].text
        rest = args[i + 1 :]
        operands = [w for w in rest if not (w.literal and w.text.startswith("-"))]
        flags = {w.text for w in rest if w.literal and w.text.startswith("-")}
        whole_tree = [Word(".", ".", True)]
        if sub == "stash":
            action = rest[0].text if rest and rest[0].literal else "push"
            if action in ("list", "show"):
                return None
            return self._check_all(whole_tree, gcwd, "remove")
        if sub == "reset":
            if flags & {"--hard", "--merge", "--keep"}:
                return self._check_all(whole_tree, gcwd, "remove")
            return None
        if sub in _GIT_PATHS:
            if sub == "clean" and not operands:
                operands = whole_tree
            return self._check_all(operands, gcwd, "remove")
        return None

    def _read_only(self, name: str, args: list[Word], cwd: str | None) -> str | None:
        if name == "sort":
            _, values, _ = self._operands(args, {"-o", "--output", "-T", "-S", "-k", "-t"})
            return self._check_all(values.get("-o", []) + values.get("--output", []), cwd, "write")
        if name == "tree":
            _, values, _ = self._operands(args, {"-o", "-L", "-P", "-I"})
            return self._check_all(values.get("-o", []), cwd, "write")
        if name == "uniq":
            operands, _, _ = self._operands(args, {"-f", "-s", "-w"})
            return self._check_all(operands[1:2], cwd, "write")
        return None


# --------------------------------------------------------------------------- public API


def scan(command: str, cwd: str | None, ctx: ScanContext, *, strict: bool = False) -> str | None:
    """Reason code for a Bash command the guard must refuse at step 2, or None.

    ``strict`` (subagents) also refuses every file write other than ``/dev/null``.
    """
    if not isinstance(command, str):
        return OPAQUE_WRITE
    return _Scanner(ctx, strict).text(command, cwd, 0)


def binding_safe(command: str, depth: int = 0) -> bool:
    """True when the command has nothing the shell expands at run time.

    Byte-equal step binding only trusts literal text: no parameter expansion, command
    substitution, backticks, globs, braces, tilde, process substitution, here-documents or
    here-strings, no assignment prefixes, no eval/source/xargs, and nested ``sh -c`` text
    must be literal too. It proves the approved string, never the effect.
    """
    if depth > MAX_DEPTH or not isinstance(command, str) or "<<" in command:
        return False
    try:
        cmds = parse(command)
    except ParseError:
        return False
    for cmd in cmds:
        if cmd.procsubs:
            return False
        if cmd.group is not None and not binding_safe(cmd.group, depth + 1):
            return False
        words = cmd.words + [r.target for r in cmd.redirs if r.target is not None]
        if any(not w.literal or w.subs for w in words):
            return False
        if any(_ASSIGN.match(w.raw) for w in cmd.words[:1]):
            return False
        for k, word in enumerate(cmd.words):
            name = _base(word)
            if name in ("eval", "source", ".", "xargs"):
                return False
            if name in _SHELLS and k + 2 < len(cmd.words):
                flag = cmd.words[k + 1].text
                if flag.startswith("-") and "c" in flag[1:]:
                    if not binding_safe(cmd.words[k + 2].text, depth + 1):
                        return False
    return True


def subagent_command_ok(
    command: str, allow: Collection[str], cwd: str | None, ctx: ScanContext
) -> bool:
    """Strict check for a subagent's not-admin Bash call.

    Every program word must be a bare name on the allow list, with no substitution,
    subshell, here-document, assignment prefix or output redirection other than
    ``/dev/null``; the command must also pass the strict scan (no file writes).
    """
    if not isinstance(command, str) or len(command) > MAX_TEXT or _authority(command):
        return False
    try:
        cmds = parse(command)
    except ParseError:
        return False
    for cmd in cmds:
        if cmd.group is not None or cmd.procsubs:
            return False
        if any(w.subs for w in cmd.words):
            return False
        for redir in cmd.redirs:
            target = redir.target
            if redir.op in _HEREDOC_OPS or redir.op == "<<<":
                return False
            if target is not None and target.subs:
                return False
            if redir.op in ("<", "<&"):
                continue
            if redir.op == ">&" and target is not None and target.literal:
                if target.text.isdigit() or target.text == "-":
                    continue
            if target is None or not target.literal or target.text != "/dev/null":
                return False
        if not cmd.words:
            continue
        head = cmd.words[0]
        if _ASSIGN.match(head.raw) or not head.literal or "/" in head.text:
            return False
        if head.text not in allow:
            return False
    return _Scanner(ctx, strict=True).text(command, cwd, 0) is None
