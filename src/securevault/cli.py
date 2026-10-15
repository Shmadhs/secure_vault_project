"""Command-line interface: ``svault <command> [options]``.

Commands are defined once and shared by the one-shot CLI and the interactive
shell (``svault shell``).

Passwords and TOTP secrets are never accepted as command-line arguments. Argv
is visible to other local users in the process list and lands in shell
history, so those are always prompted for with echo off. Usernames, URLs, tags
and notes *are* accepted as arguments for convenience. Inside ``svault shell``
nothing reaches argv, which makes it the right place for sensitive notes.
"""

from __future__ import annotations

import argparse
import codecs
import copy
import getpass
import io
import os
import re
import shlex
import sys
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from . import __version__, clipboard, crypto, generator, osutil, storage, totp, transfer
from .audit import audit
from .crypto import KdfParams
from .errors import AuthenticationError, IntegrityError, VaultError, VaultExistsError
from .model import Entry
from .vault import Vault, read_header, restore_backup
from .vault_format import FORMAT_VERSION

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_AUTH, EXIT_INTEGRITY, EXIT_INTERRUPTED = 0, 1, 2, 3, 4, 130
MIN_MASTER_BITS = 60.0
DEFAULT_IDLE_MINUTES = 5

Handler = Callable[["Context", argparse.Namespace], int]

# --------------------------------------------------------------------------- terminal I/O

# C0/C1 control characters (except tab and newline) and Unicode bidi overrides.
# Data imported from elsewhere could otherwise carry escape sequences that
# rewrite the terminal, or even set the clipboard through OSC 52.
_UNSAFE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def term_safe(text: str, *, multiline: bool = False) -> str:
    if not multiline:
        text = text.replace("\n", " ")
    return _UNSAFE.sub(lambda m: f"\\u{ord(m.group()):04x}", text)


def read_secret(prompt: str) -> str:
    """Prompt with echo disabled. Refuses when stdin is not a terminal.

    Under Git Bash's mintty, stdin is a pipe and Python cannot turn echo off,
    so the password would show. We stop and explain instead.
    """
    if not sys.stdin.isatty():
        raise VaultError(
            "stdin is not a terminal, so the password cannot be read without echo. "
            "Use Windows Terminal/PowerShell, or prefix the command with 'winpty' in Git Bash; "
            "for scripts use --password-stdin"
        )
    return getpass.getpass(prompt)


def read_line(prompt: str) -> str:
    """Read a line, printing the prompt on stderr so stdout stays clean for piping."""
    sys.stderr.write(prompt)
    sys.stderr.flush()
    return input()


def confirm(prompt: str, *, default: bool = False) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    answer = read_line(prompt + suffix).strip().casefold()
    return default if not answer else answer in {"y", "yes", "ν", "ναι"}


def _truncate(text: str, width: int) -> str:
    text = term_safe(text)
    return text if len(text) <= width else text[: width - 1] + "…"


# --------------------------------------------------------------------------- context


@dataclass
class Context:
    vault_path: Path
    keyfile_path: Path | None = None
    password_stdin: bool = False
    out: TextIO = field(default_factory=lambda: sys.stdout)
    err: TextIO = field(default_factory=lambda: sys.stderr)
    interactive: bool = False
    _vault: Vault | None = None

    def say(self, message: str = "") -> None:
        self.out.write(message + "\n")

    def warn(self, message: str) -> None:
        self.err.write(message + "\n")

    def keyfile(self) -> bytes | None:
        return crypto.keyfile_secret(self.keyfile_path) if self.keyfile_path else None

    def master_password(self, prompt: str) -> str:
        """Prompt for a master password, or take the next stdin line with --password-stdin.

        With --password-stdin each request consumes one line, so ``passwd``
        reads the current password, then the new one.
        """
        if self.password_stdin:
            line = sys.stdin.readline()
            if not line:
                raise VaultError("--password-stdin: no more input on stdin")
            return line.rstrip("\r\n")
        return read_secret(prompt)

    def vault(self) -> Vault:
        """The unlocked vault, prompting for the master password if needed."""
        if self._vault is not None and not self._vault.locked:
            return self._vault
        if osutil.is_group_or_world_accessible(self.vault_path):
            self.warn(f"warning: {self.vault_path} is readable by other users (chmod 600 it)")
        keyfile = self.keyfile()
        attempts = 3 if self.interactive else 1
        for attempt in range(1, attempts + 1):
            password = self.master_password(f"Master password ({self.vault_path.name}): ")
            try:
                self._vault = Vault.open(self.vault_path, password, keyfile=keyfile)
                return self._vault
            except AuthenticationError:
                if attempt == attempts:
                    raise
                self.warn("Wrong master password or keyfile, try again.")
        raise AssertionError("unreachable")

    def lock(self) -> None:
        if self._vault is not None:
            self._vault.lock()
        self._vault = None


def _new_master_password(ctx: Context) -> str:
    """Interactively choose a master password, offering a generated passphrase."""
    if ctx.password_stdin:
        return ctx.master_password("")
    if confirm("Generate a strong master passphrase for you?", default=True):
        phrase = generator.generate_passphrase(6)
        bits = generator.passphrase_entropy(6)
        ctx.say(f"\n  Your master passphrase ({bits:.0f} bits):\n\n      {phrase}\n")
        ctx.say("  Write it on paper and keep it somewhere safe. It is shown only once")
        ctx.say("  and cannot be recovered: there is no 'forgot password'.\n")
        while True:
            typed = read_secret("Type it back to confirm you recorded it: ")
            if typed == phrase:
                return phrase
            ctx.warn("That does not match. Check what you wrote down.")
    while True:
        first = read_secret("New master password: ")
        if not first:
            ctx.warn("The master password must not be empty.")
            continue
        if read_secret("Repeat it: ") != first:
            ctx.warn("The passwords do not match.")
            continue
        bits = generator.estimate_strength(first)
        if bits < MIN_MASTER_BITS:
            ctx.warn(
                f"That password is weak (about {bits:.0f} bits; at least {MIN_MASTER_BITS:.0f} "
                "recommended). A six-word passphrase is easy to remember and much stronger."
            )
            if not confirm("Use it anyway?"):
                continue
        return first


def _prompt_entry_password(ctx: Context) -> str:
    while True:
        first = read_secret("Entry password (leave empty for none): ")
        if not first or read_secret("Repeat it: ") == first:
            return first
        ctx.warn("The passwords do not match.")


def _prompt_totp() -> str:
    value = read_secret("TOTP secret or otpauth:// URI: ").strip()
    totp.parse(value)  # validate before storing
    return value


def _generated(args: argparse.Namespace) -> tuple[str, float] | None:
    if getattr(args, "passphrase", False):
        return generator.generate_passphrase(args.words), generator.passphrase_entropy(args.words)
    if getattr(args, "generate", False):
        classes = generator.build_alphabet()
        pw = generator.generate_password(args.length)
        return pw, generator.password_entropy(args.length, len("".join(classes)))
    return None


def _split_tags(raw: str | None) -> list[str]:
    return [t.strip() for t in (raw or "").split(",") if t.strip()]


# --------------------------------------------------------------------------- commands


def cmd_init(ctx: Context, args: argparse.Namespace) -> int:
    path = ctx.vault_path
    if path.exists():
        raise VaultExistsError(f"a vault already exists at {path}")
    if args.new_keyfile:
        _create_keyfile(Path(args.new_keyfile))
        ctx.keyfile_path = Path(args.new_keyfile)
        ctx.say(f"Created keyfile {args.new_keyfile}. Back it up: without it the vault cannot be opened.")
    keyfile = ctx.keyfile()
    ctx.say(f"Creating a new vault at {path}")
    password = _new_master_password(ctx)
    ctx.say("Calibrating key derivation for this computer...")
    kdf = _kdf_from_args(args)
    vault = Vault.create(path, password, kdf=kdf, keyfile=keyfile)
    vault.lock()
    ctx.say(
        f"Vault created. Argon2id: {kdf.memory_mib:.0f} MiB, {kdf.iterations} iterations, "
        f"{kdf.lanes} lanes{' + keyfile' if keyfile else ''}."
    )
    return EXIT_OK


def _kdf_from_args(args: argparse.Namespace) -> KdfParams:
    memory = args.kdf_memory * 1024 if args.kdf_memory else None
    params = crypto.calibrate_kdf(args.unlock_time, memory_kib=memory, lanes=args.kdf_parallelism)
    if args.kdf_iterations:
        params = KdfParams(params.salt, params.memory_kib, args.kdf_iterations, params.lanes)
        crypto.check_kdf_params(params)
    return params


def _create_keyfile(path: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise VaultError(f"{path} already exists; refusing to overwrite a keyfile") from None
    with os.fdopen(fd, "wb") as fh:
        fh.write(crypto.generate_keyfile_bytes())


def cmd_keyfile(ctx: Context, args: argparse.Namespace) -> int:
    _create_keyfile(Path(args.path))
    ctx.say(f"Created keyfile {args.path} (64 random bytes).")
    ctx.say("Keep a backup copy offline. Losing it locks you out just like losing the password.")
    return EXIT_OK


def cmd_add(ctx: Context, args: argparse.Namespace) -> int:
    vault = ctx.vault()
    generated = _generated(args)
    password = generated[0] if generated else _prompt_entry_password(ctx)
    entry = Entry(
        title=args.title,
        username=args.username or "",
        password=password,
        url=args.url or "",
        notes=args.notes or "",
        tags=_split_tags(args.tags),
        totp=_prompt_totp() if args.totp else "",
    )
    vault.add(entry)
    vault.save()
    detail = f" with a generated {generated[1]:.0f}-bit password" if generated else ""
    ctx.say(f"Added '{term_safe(entry.title)}'{detail}.")
    return EXIT_OK


def _field_value(entry: Entry, name: str) -> str:
    if name == "totp":
        if not entry.totp:
            raise VaultError(f"'{entry.title}' has no TOTP secret")
        return totp.now(totp.parse(entry.totp))[0]
    value: str = getattr(entry, name)
    if not value:
        raise VaultError(f"'{entry.title}' has no {name}")
    return value


def _deliver(ctx: Context, value: str, label: str, *, to_stdout: bool, seconds: int) -> None:
    if to_stdout:
        ctx.say(value)
        return
    scheduled = clipboard.copy_with_autoclear(value, seconds)
    tail = f"; it will be cleared in {seconds} s" if scheduled else ""
    ctx.say(f"Copied {label} to the clipboard{tail}.")
    if seconds > 0 and not scheduled:
        ctx.warn("warning: could not start the auto-clear helper; clear the clipboard yourself")


def cmd_get(ctx: Context, args: argparse.Namespace) -> int:
    entry = ctx.vault().find(args.query)
    value = _field_value(entry, args.field)
    _deliver(
        ctx,
        value,
        f"the {args.field} of '{term_safe(entry.title)}'",
        to_stdout=args.print,
        seconds=args.clear_after,
    )
    return EXIT_OK


def cmd_show(ctx: Context, args: argparse.Namespace) -> int:
    entry = ctx.vault().find(args.query)
    rows = [
        ("Title", entry.title),
        ("Username", entry.username),
        ("Password", entry.password if args.reveal else ("•" * 10 if entry.password else "")),
        ("URL", entry.url),
        ("Tags", ", ".join(entry.tags)),
        ("TOTP", "configured" if entry.totp else ""),
        ("Created", entry.created),
        ("Modified", entry.modified),
        ("History", f"{len(entry.history)} previous password(s)" if entry.history else ""),
        ("ID", entry.id),
    ]
    for label, value in rows:
        if value:
            ctx.say(f"{label:>9}: {term_safe(value)}")
    if entry.notes:
        ctx.say("    Notes:")
        for line in term_safe(entry.notes, multiline=True).splitlines():
            ctx.say(f"      {line}")
    return EXIT_OK


def _print_table(ctx: Context, entries: Sequence[Entry]) -> None:
    if not entries:
        ctx.say("No entries.")
        return
    ctx.say(f"{'TITLE':<30} {'USERNAME':<26} {'URL':<34} TAGS")
    for e in entries:
        ctx.say(
            f"{_truncate(e.title, 30):<30} {_truncate(e.username, 26):<26} "
            f"{_truncate(e.url, 34):<34} {_truncate(', '.join(e.tags), 30)}"
        )


def cmd_list(ctx: Context, args: argparse.Namespace) -> int:
    contents = ctx.vault().contents
    entries = [e for e in contents if not args.tag or args.tag.casefold() in (t.casefold() for t in e.tags)]
    if not len(contents):
        ctx.say("The vault is empty. Add an entry with: svault add <title>")
        return EXIT_OK
    _print_table(ctx, entries)
    return EXIT_OK


def cmd_search(ctx: Context, args: argparse.Namespace) -> int:
    _print_table(ctx, ctx.vault().contents.search(args.term))
    return EXIT_OK


def cmd_edit(ctx: Context, args: argparse.Namespace) -> int:
    vault = ctx.vault()
    entry = vault.find(args.query)
    changed: list[str] = []
    if args.title is not None:
        vault.contents.rename(entry, args.title)
        changed.append("title")
    for name in ("username", "url", "notes"):
        value = getattr(args, name)
        if value is not None:
            setattr(entry, name, value)
            changed.append(name)
    if args.tags is not None:
        entry.tags = _split_tags(args.tags)
        changed.append("tags")
    generated = _generated(args)
    if generated:
        entry.set_password(generated[0])
        changed.append("password (generated)")
    elif args.password:
        entry.set_password(_prompt_entry_password(ctx))
        changed.append("password")
    if args.totp:
        entry.totp = _prompt_totp()
        changed.append("totp")
    elif args.clear_totp:
        entry.totp = ""
        changed.append("totp (removed)")
    if not changed:
        raise VaultError("nothing to change (see 'svault edit --help')")
    entry.touch()
    vault.save()
    ctx.say(f"Updated {', '.join(changed)} of '{term_safe(entry.title)}'.")
    return EXIT_OK


def cmd_rm(ctx: Context, args: argparse.Namespace) -> int:
    vault = ctx.vault()
    # Deletion needs an exact title or id prefix. A fuzzy search match combined
    # with --yes could delete the wrong entry without anyone seeing which.
    entry = vault.contents.find(args.query, fuzzy=False)
    if not args.yes and not confirm(f"Delete '{term_safe(entry.title)}'?"):
        ctx.say("Cancelled.")
        return EXIT_OK
    vault.contents.remove(entry)
    vault.save()
    ctx.say(f"Deleted '{term_safe(entry.title)}'. A previous version remains in the encrypted backups.")
    return EXIT_OK


def cmd_gen(ctx: Context, args: argparse.Namespace) -> int:
    if args.words:
        value = generator.generate_passphrase(args.words, args.separator, capitalize=args.capitalize)
        bits = generator.passphrase_entropy(args.words)
    else:
        classes = generator.build_alphabet(
            lower=not args.no_lower,
            upper=not args.no_upper,
            digits=not args.no_digits,
            symbols=not args.no_symbols,
            exclude_ambiguous=args.exclude_ambiguous,
        )
        value = generator.generate_password(
            args.length,
            lower=not args.no_lower,
            upper=not args.no_upper,
            digits=not args.no_digits,
            symbols=not args.no_symbols,
            exclude_ambiguous=args.exclude_ambiguous,
        )
        bits = generator.password_entropy(args.length, len("".join(classes)))
    ctx.warn(f"entropy: {bits:.0f} bits")
    _deliver(ctx, value, "the generated value", to_stdout=not args.copy, seconds=args.clear_after)
    return EXIT_OK


def cmd_totp(ctx: Context, args: argparse.Namespace) -> int:
    entry = ctx.vault().find(args.query)
    if not entry.totp:
        raise VaultError(f"'{entry.title}' has no TOTP secret")
    code, remaining = totp.now(totp.parse(entry.totp))
    if args.copy:
        _deliver(ctx, code, f"the TOTP code ({remaining} s left)", to_stdout=False, seconds=remaining + 1)
    else:
        ctx.say(f"{code}  (valid for {remaining} s)")
    return EXIT_OK


def cmd_audit(ctx: Context, args: argparse.Namespace) -> int:
    contents = ctx.vault().contents
    findings = audit(contents, max_age_days=args.max_age_days)
    if not findings:
        ctx.say(f"All {len(contents)} entries look healthy.")
        return EXIT_OK
    for f in findings:
        ctx.say(f"[{f.kind.upper():<6}] {_truncate(f.entry.title, 40):<40} {term_safe(f.detail)}")
    kinds = sorted({f.kind for f in findings})
    ctx.say(f"\n{len(findings)} finding(s): " + ", ".join(f"{k}={sum(f.kind == k for f in findings)}" for k in kinds))
    return EXIT_OK


def cmd_passwd(ctx: Context, args: argparse.Namespace) -> int:
    vault = ctx.vault()
    keyfile: bytes | None = ctx.keyfile() if vault.uses_keyfile else None
    if args.remove_keyfile:
        keyfile = None
    if args.new_keyfile:
        _create_keyfile(Path(args.new_keyfile))
        keyfile = crypto.keyfile_secret(Path(args.new_keyfile))
        ctx.say(f"Created keyfile {args.new_keyfile}. Back it up.")
    ctx.say("Choose the new master password.")
    password = _new_master_password(ctx)
    kdf = None
    if args.recalibrate:
        ctx.say("Re-calibrating key derivation...")
        kdf = crypto.calibrate_kdf(args.unlock_time)
    removed = vault.change_master_password(password, keyfile=keyfile, kdf=kdf)
    ctx.say("Master password changed. The vault key was rotated and everything re-encrypted.")
    if removed:
        ctx.say(f"Removed {removed} old backup(s) encrypted under the previous key.")
    return EXIT_OK


def cmd_import(ctx: Context, args: argparse.Namespace) -> int:
    vault = ctx.vault()
    try:
        with open(args.file, encoding="utf-8-sig", newline="") as fh:
            rows = transfer.read_csv(fh)
    except OSError as exc:
        raise VaultError(f"cannot read {args.file}: {exc.strerror or exc}") from exc
    target = copy.deepcopy(vault.contents) if args.dry_run else vault.contents
    result = transfer.import_rows(target, rows)
    for old, new in result.renamed:
        ctx.say(f"  renamed duplicate '{term_safe(old)}' -> '{term_safe(new)}'")
    if args.dry_run:
        ctx.say(f"Dry run: would import {len(result.added)} entries ({result.skipped} empty rows skipped).")
        return EXIT_OK
    vault.save()
    ctx.say(f"Imported {len(result.added)} entries ({result.skipped} empty rows skipped).")
    ctx.say(f"Now delete the plaintext file '{args.file}', and empty the recycle bin/trash.")
    return EXIT_OK


def cmd_export(ctx: Context, args: argparse.Namespace) -> int:
    vault = ctx.vault()
    entries = list(vault.contents)
    text = transfer.export_json(entries) if args.format == "json" else transfer.export_csv(entries)
    ctx.warn(f"This writes {len(entries)} entries in PLAINTEXT. Anyone who can read the file gets every password.")
    if read_line("Type 'export' to continue: ").strip() != "export":
        ctx.say("Cancelled.")
        return EXIT_OK
    if args.file == "-":
        ctx.out.write(text)
        return EXIT_OK
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(args.file, flags, 0o600)
    except FileExistsError:
        raise VaultError(f"{args.file} already exists; refusing to overwrite") from None
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    ctx.say(f"Exported {len(entries)} entries to {args.file}.")
    return EXIT_OK


def cmd_info(ctx: Context, args: argparse.Namespace) -> int:
    path = ctx.vault_path
    header = read_header(path)
    ctx.say(f"Vault:      {path}")
    ctx.say(f"Size:       {path.stat().st_size} bytes (format v{FORMAT_VERSION}, AES-256-GCM)")
    ctx.say(f"Vault id:   {header.vault_id}")
    for i, slot in enumerate(header.slots, 1):
        k = slot.kdf
        ctx.say(
            f"Key slot {i}: Argon2id {k.memory_mib:.0f} MiB, t={k.iterations}, p={k.lanes}"
            f"{', keyfile required' if slot.keyfile else ''}"
        )
    ctx.say(f"Backups:    {len(storage.list_backups(path))} in {storage.backup_dir(path)}")
    hardening = osutil.harden_process()
    ctx.say(f"Hardening:  {', '.join(hardening) if hardening else 'none available on this OS'}")
    if osutil.is_group_or_world_accessible(path):
        ctx.warn("warning: the vault file is readable by other users (chmod 600 it)")
    return EXIT_OK


def cmd_backups(ctx: Context, args: argparse.Namespace) -> int:
    backups = storage.list_backups(ctx.vault_path)
    if not backups:
        ctx.say(f"No backups in {storage.backup_dir(ctx.vault_path)}.")
        return EXIT_OK
    ctx.say(f"Encrypted backups of {ctx.vault_path.name}, newest first:")
    for number, path in enumerate(backups, 1):
        ctx.say(f"  {number}. {path.name}  ({path.stat().st_size} bytes)")
    ctx.say("Restore one with: svault restore <number>")
    return EXIT_OK


def cmd_restore(ctx: Context, args: argparse.Namespace) -> int:
    backups = storage.list_backups(ctx.vault_path)
    if not 1 <= args.number <= len(backups):
        raise VaultError(f"no backup number {args.number} (see 'svault backups')")
    backup = backups[args.number - 1]
    password = ctx.master_password(f"Master password for backup {backup.name}: ")
    if not confirm(f"Replace {ctx.vault_path.name} with {backup.name}? The current file is kept as a backup."):
        ctx.say("Cancelled.")
        return EXIT_OK
    count = restore_backup(ctx.vault_path, backup, password, keyfile=ctx.keyfile())
    ctx.say(f"Restored {count} entries from {backup.name}.")
    return EXIT_OK


def cmd_shell(ctx: Context, args: argparse.Namespace) -> int:
    return run_shell(ctx, args.idle_minutes)


# --------------------------------------------------------------------------- parser


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return number


def _add_generation_options(p: argparse.ArgumentParser) -> None:
    group = p.add_mutually_exclusive_group()
    group.add_argument("-g", "--generate", action="store_true", help="generate a random password")
    group.add_argument("--passphrase", action="store_true", help="generate a diceware passphrase")
    p.add_argument("--length", type=int, default=24, help="generated password length (default 24)")
    p.add_argument("--words", type=int, default=6, help="passphrase word count (default 6)")


def _add_vault_commands(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("add", help="add an entry")
    p.add_argument("title")
    p.add_argument("-u", "--username")
    p.add_argument("--url")
    p.add_argument("--notes")
    p.add_argument("--tags", help="comma-separated")
    p.add_argument("--totp", action="store_true", help="prompt for a TOTP secret / otpauth URI")
    _add_generation_options(p)
    p.set_defaults(handler=cmd_add)

    p = sub.add_parser("get", help="copy a field to the clipboard (default: password)")
    p.add_argument("query", help="title, unique search term, or id prefix")
    p.add_argument("-f", "--field", default="password", choices=["password", "username", "url", "totp", "notes"])
    p.add_argument("--print", action="store_true", help="print to stdout instead of copying")
    p.add_argument("--clear-after", type=_positive_int, default=clipboard.DEFAULT_CLEAR_SECONDS, metavar="SEC")
    p.set_defaults(handler=cmd_get)

    p = sub.add_parser("show", help="show an entry (password hidden unless --reveal)")
    p.add_argument("query")
    p.add_argument("--reveal", action="store_true")
    p.set_defaults(handler=cmd_show)

    p = sub.add_parser("list", aliases=["ls"], help="list entries")
    p.add_argument("--tag")
    p.set_defaults(handler=cmd_list)

    p = sub.add_parser("search", help="search titles, usernames, URLs, tags and notes")
    p.add_argument("term")
    p.set_defaults(handler=cmd_search)

    p = sub.add_parser("edit", help="change fields of an entry")
    p.add_argument("query")
    p.add_argument("--title")
    p.add_argument("-u", "--username")
    p.add_argument("--url")
    p.add_argument("--notes")
    p.add_argument("--tags", help="replace tags (comma-separated)")
    p.add_argument("--password", action="store_true", help="prompt for a new password")
    totp_group = p.add_mutually_exclusive_group()
    totp_group.add_argument("--totp", action="store_true", help="prompt for a new TOTP secret")
    totp_group.add_argument("--clear-totp", action="store_true")
    _add_generation_options(p)
    p.set_defaults(handler=cmd_edit)

    p = sub.add_parser("rm", aliases=["delete"], help="delete an entry")
    p.add_argument("query")
    p.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    p.set_defaults(handler=cmd_rm)

    p = sub.add_parser("gen", help="generate a password or passphrase (no vault needed)")
    p.add_argument("--length", type=int, default=24)
    p.add_argument("--words", type=int, help="generate a passphrase with this many words")
    p.add_argument("--separator", default="-")
    p.add_argument("--capitalize", action="store_true")
    p.add_argument("--no-lower", action="store_true")
    p.add_argument("--no-upper", action="store_true")
    p.add_argument("--no-digits", action="store_true")
    p.add_argument("--no-symbols", action="store_true")
    p.add_argument("--exclude-ambiguous", action="store_true", help="avoid look-alikes such as l/1/O/0")
    p.add_argument("--copy", action="store_true", help="copy instead of printing")
    p.add_argument("--clear-after", type=_positive_int, default=clipboard.DEFAULT_CLEAR_SECONDS, metavar="SEC")
    p.set_defaults(handler=cmd_gen)

    p = sub.add_parser("totp", help="show the current TOTP code of an entry")
    p.add_argument("query")
    p.add_argument("--copy", action="store_true")
    p.set_defaults(handler=cmd_totp)

    p = sub.add_parser("audit", help="report reused, weak and old passwords")
    p.add_argument("--max-age-days", type=int, default=365)
    p.set_defaults(handler=cmd_audit)

    p = sub.add_parser("passwd", help="change the master password (rotates the vault key)")
    kf = p.add_mutually_exclusive_group()
    kf.add_argument("--new-keyfile", metavar="PATH", help="create a new keyfile and require it")
    kf.add_argument("--remove-keyfile", action="store_true", help="stop requiring a keyfile")
    p.add_argument("--recalibrate", action="store_true", help="re-tune Argon2id for this computer")
    p.add_argument("--unlock-time", type=float, default=crypto.DEFAULT_UNLOCK_SECONDS)
    p.set_defaults(handler=cmd_passwd)

    p = sub.add_parser("import", help="import a CSV export (Bitwarden, KeePassXC, Chrome, Firefox...)")
    p.add_argument("file")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(handler=cmd_import)

    p = sub.add_parser("export", help="export entries as PLAINTEXT csv/json")
    p.add_argument("file", help="output path, or - for stdout")
    p.add_argument("--format", choices=["csv", "json"], default="json")
    p.set_defaults(handler=cmd_export)

    p = sub.add_parser("info", help="show vault file details (no password needed)")
    p.set_defaults(handler=cmd_info)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="svault",
        description="SecureVault: an offline password manager (Argon2id + AES-256-GCM).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--vault",
        type=Path,
        default=Path(os.environ["SVAULT_VAULT"]) if os.environ.get("SVAULT_VAULT") else None,
        help="vault file (default: $SVAULT_VAULT or the per-user data directory)",
    )
    parser.add_argument(
        "--keyfile",
        type=Path,
        default=Path(os.environ["SVAULT_KEYFILE"]) if os.environ.get("SVAULT_KEYFILE") else None,
        help="keyfile required by the vault (default: $SVAULT_KEYFILE)",
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the master password from the first line of stdin (for scripts)",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p = sub.add_parser("init", help="create a new vault")
    p.add_argument("--new-keyfile", metavar="PATH", help="also create and require a keyfile")
    p.add_argument(
        "--unlock-time",
        type=float,
        default=crypto.DEFAULT_UNLOCK_SECONDS,
        metavar="SEC",
        help="target unlock time for Argon2id calibration (default 1.0)",
    )
    p.add_argument("--kdf-memory", type=int, metavar="MIB", help="Argon2id memory (default: auto, up to 1024)")
    p.add_argument("--kdf-iterations", type=int, metavar="N", help="Argon2id iterations (default: calibrated)")
    p.add_argument("--kdf-parallelism", type=int, default=crypto.DEFAULT_LANES, metavar="N")
    p.set_defaults(handler=cmd_init)

    p = sub.add_parser("keyfile", help="create a new random keyfile")
    p.add_argument("path")
    p.set_defaults(handler=cmd_keyfile)

    p = sub.add_parser("shell", help="interactive session that auto-locks when idle")
    p.add_argument("--idle-minutes", type=_positive_int, default=DEFAULT_IDLE_MINUTES)
    p.set_defaults(handler=cmd_shell)

    p = sub.add_parser("backups", help="list the encrypted automatic backups")
    p.set_defaults(handler=cmd_backups)

    p = sub.add_parser("restore", help="replace the vault with a verified backup")
    p.add_argument("number", type=int, help="backup number from 'svault backups' (1 = newest)")
    p.set_defaults(handler=cmd_restore)

    _add_vault_commands(sub)
    return parser


def build_shell_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="", add_help=False, usage=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    _add_vault_commands(sub)
    return parser


# --------------------------------------------------------------------------- running


def run_handler(ctx: Context, handler: Handler, args: argparse.Namespace) -> int:
    """Run a command and translate errors into messages and exit codes."""
    try:
        return handler(ctx, args)
    except AuthenticationError as exc:
        ctx.warn(f"error: {exc}")
        return EXIT_AUTH
    except IntegrityError as exc:
        ctx.warn(f"INTEGRITY FAILURE: {exc}")
        return EXIT_INTEGRITY
    except (VaultError, clipboard.ClipboardUnavailableError, ValueError) as exc:
        ctx.warn(f"error: {exc}")
        return EXIT_ERROR
    except OSError as exc:  # disk full, permission denied, read-only media...
        where = f" ({exc.filename})" if exc.filename else ""
        ctx.warn(f"error: {exc.strerror or exc}{where}")
        return EXIT_ERROR
    except EOFError:
        ctx.warn("\nerror: input ended")
        return EXIT_ERROR


class _IdleLock:
    """Locks the vault after ``seconds`` without a command.

    ``cancel()`` and the timer callback share a lock. Once ``cancel()``
    returns, the timer can no longer lock the vault, and a lock already in
    progress has finished. So a command never runs while the vault is being
    locked under it.
    """

    def __init__(self, ctx: Context, seconds: float) -> None:
        self._ctx, self._seconds = ctx, seconds
        self._timer: threading.Timer | None = None
        self._guard = threading.Lock()
        self._armed = False
        self.fired = False

    def _fire(self) -> None:
        with self._guard:
            if not self._armed:
                return
            self._armed = False
            self.fired = True
            self._ctx.lock()
        self._ctx.warn(f"\n[auto-locked after {self._seconds / 60:.0f} min of inactivity]")

    def arm(self) -> None:
        self.cancel()
        if self._seconds > 0:
            with self._guard:
                self._armed = True
                self._timer = threading.Timer(self._seconds, self._fire)
                self._timer.daemon = True
                self._timer.start()

    def cancel(self) -> None:
        with self._guard:
            self._armed = False
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None


SHELL_HELP = """Commands (append --help to any of them for options):
  add, get, show, list, search, edit, rm, gen, totp, audit, passwd, import, export, info
  lock    lock now (the next command asks for the password again)
  exit    leave the shell"""


def run_shell(ctx: Context, idle_minutes: int) -> int:
    ctx.interactive = True
    ctx.vault()
    parser = build_shell_parser()
    idle = _IdleLock(ctx, idle_minutes * 60)
    ctx.say(f"Vault unlocked. Type 'help' for commands. Auto-locks after {idle_minutes} min idle.")
    try:
        while True:
            idle.arm()
            try:
                line = read_line("svault> ")
            except EOFError:
                ctx.say()
                break
            except KeyboardInterrupt:
                ctx.say()
                continue
            finally:
                idle.cancel()
            try:
                words = shlex.split(line)
            except ValueError as exc:
                ctx.warn(f"error: {exc}")
                continue
            if not words:
                continue
            if words[0] in {"exit", "quit"}:
                break
            if words[0] in {"help", "?"}:
                ctx.say(SHELL_HELP)
                continue
            if words[0] == "lock":
                ctx.lock()
                ctx.say("Locked.")
                continue
            try:
                args = parser.parse_args(words)
            except SystemExit:
                continue  # argparse already printed the problem or the help text
            if getattr(args, "handler", None) is None:
                ctx.warn(f"unknown command: {words[0]} (try 'help')")
                continue
            try:
                run_handler(ctx, args.handler, args)
            except KeyboardInterrupt:
                ctx.say("\nCancelled.")
    finally:
        idle.cancel()
        ctx.lock()
    ctx.say("Vault locked. Bye.")
    return EXIT_OK


def configure_stdio() -> None:
    """Force UTF-8 on redirected standard streams.

    On Windows, pipes and redirected files default to the ANSI code page
    (cp1252/cp1253). That is a correctness bug, not a cosmetic one. A Greek
    master password piped through --password-stdin would decode to different
    characters than the same password typed at the console, and derive a
    different key. Interactive consoles already use UTF-16 and are unaffected.
    """
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper) and codecs.lookup(stream.encoding).name != "utf-8":
            stream.reconfigure(encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == [clipboard.HELPER_COMMAND]:
        seconds = int(arguments[1]) if len(arguments) > 1 and arguments[1].isdigit() else 0
        return clipboard.run_helper(seconds)
    configure_stdio()
    osutil.harden_process()
    parser = build_parser()
    args = parser.parse_args(arguments)
    if not getattr(args, "handler", None):
        parser.print_help()
        return EXIT_USAGE
    ctx = Context(
        vault_path=args.vault or osutil.default_vault_path(),
        keyfile_path=args.keyfile,
        password_stdin=args.password_stdin,
    )
    try:
        return run_handler(ctx, args.handler, args)
    except KeyboardInterrupt:
        ctx.warn("\nInterrupted.")
        return EXIT_INTERRUPTED
    finally:
        ctx.lock()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
