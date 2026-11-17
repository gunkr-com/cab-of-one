"""Invariant tests for cab_of_one.setup.tomlw. No files are written."""

from __future__ import annotations

import copy
import datetime
import enum
import math
import random
import tomllib
import unittest
from types import MappingProxyType
from typing import Any

from cab_of_one.setup import tomlw

# Fictional reference profile (DESIGN §10-4-3 shape, Contoso data only).
CONTOSO = {
    "schema": 1,
    "org": {"name": "Contoso", "it_team": "solo"},
    "systems": {
        "entra": True,
        "exchange_online": True,
        "intune": True,
        "sharepoint_teams": False,
        "azure": True,
        "demo_simtenant": True,
    },
    "surfaces": {
        "powershell_modules": ["Microsoft.Graph", "ExchangeOnlineManagement"],
        "azure_cli": True,
        "graph_http": True,
        "mcp_write_servers": [],
    },
    "identity": {"agent_identity": "admin", "deny_read_paths": ["./secrets/**"]},
    "approval": {"approvers": "self", "approval_ttl_hours": 4},
    "session": {
        "permission_mode": "bypass-guarded",
        "git": True,
        "multi_machine": True,
        "sync_folder": False,
        "ticketing": "none",
    },
    "changes": {
        "routine": ["group-add-allowlisted", "forwarding-removal"],
        "extra_critical": ["break-glass", "executive-mailboxes"],
    },
}

TRICKY_STRINGS = [
    "",
    'say "hi"',
    "back\\slash \\n not a newline",
    "line1\nline2\r\nline3",
    "tab\there",
    "\x00\x01\x08\x0b\x0c\x1b\x1f\x7f\x80\x9f",
    "éè 中文 한국어 \U0001f600 é",
    "  ﻿",
    "'single' and '''triple'''",
    '"""triple double"""',
    "# not a comment",
    "[not.a.table]",
    "key = value",
    "trailing space ",
]


def reordered(value: Any, rng: random.Random) -> Any:
    """Same content, different dict insertion order (recursively)."""
    if isinstance(value, dict):
        keys = list(value)
        rng.shuffle(keys)
        return {key: reordered(value[key], rng) for key in keys}
    return value


def random_text(rng: random.Random) -> str:
    chars = []
    for _ in range(rng.randint(0, 12)):
        pick = rng.random()
        if pick < 0.4:
            chars.append(rng.choice("abcXYZ019_-. \"\\'#[]=\n\r\t"))
        elif pick < 0.6:
            chars.append(chr(rng.randint(0, 0x7F)))
        else:
            code = rng.randint(0x80, 0x10FFFF)
            while 0xD800 <= code <= 0xDFFF:
                code = rng.randint(0x80, 0x10FFFF)
            chars.append(chr(code))
    return "".join(chars)


def random_scalar(rng: random.Random) -> Any:
    kind = rng.randrange(4)
    if kind == 0:
        return random_text(rng)
    if kind == 1:
        return rng.randint(-(2**63), 2**63 - 1)
    if kind == 2:
        return rng.random() * 10.0 ** rng.randint(-300, 300) * rng.choice((1, -1))
    return rng.random() < 0.5


def random_table(rng: random.Random, depth: int) -> dict[str, Any]:
    table: dict[str, Any] = {}
    for _ in range(rng.randint(0, 5)):
        key = random_text(rng)
        roll = rng.random()
        if roll < 0.2 and depth < 4:
            table[key] = random_table(rng, depth + 1)
        elif roll < 0.4:
            table[key] = [random_scalar(rng) for _ in range(rng.randint(0, 4))]
        else:
            table[key] = random_scalar(rng)
    return table


class RoundTripTests(unittest.TestCase):
    def assert_round_trip(self, value: dict[str, Any]) -> str:
        text = tomlw.dumps(value)
        self.assertIsInstance(text, str)
        self.assertEqual(tomllib.loads(text), value)
        return text

    def test_contoso_profile(self) -> None:
        self.assert_round_trip(CONTOSO)

    def test_tricky_strings_as_values_keys_and_array_items(self) -> None:
        for text in TRICKY_STRINGS:
            with self.subTest(text=text):
                self.assert_round_trip({"value": text})
                self.assert_round_trip({text: 1})
                self.assert_round_trip({"t": {text: {text: text}}})
                self.assert_round_trip({"arr": [text, text + "x"]})

    def test_keys_that_look_like_syntax(self) -> None:
        for key in ("a.b", "a b", "1", "true", "inf", "nan", "-", "_", "[x]", "=", "한글"):
            with self.subTest(key=key):
                self.assert_round_trip({key: {key: key}, "plain": {key: 1}})

    def test_dotted_key_does_not_collide_with_nesting(self) -> None:
        self.assert_round_trip({"a.b": 1, "a": {"b": 2}})
        self.assert_round_trip({"a": {"b.c": 1, "b": {"c": 2}}})

    def test_nested_and_empty_tables(self) -> None:
        self.assert_round_trip({})
        self.assert_round_trip({"empty": {}})
        self.assert_round_trip({"a": {"b": {"c": {"d": {}}}}, "z": 1})
        self.assert_round_trip({"a": {"b": {"x": 1}}, "a2": {"b": {"x": 2}}})

    def test_arrays(self) -> None:
        self.assert_round_trip({"empty": [], "mixed": ["a", 1, 2.5, True, False]})
        self.assert_round_trip({"t": {"ints": [0, -1, 2**63 - 1, -(2**63)]}})

    def test_numbers(self) -> None:
        floats = [0.0, -0.0, 0.1, -1.5, 1e16, 1.5e-7, 5e-324, 1.7976931348623157e308, 123456.789]
        for number in floats:
            with self.subTest(number=number):
                text = self.assert_round_trip({"f": number})
                parsed = tomllib.loads(text)["f"]
                self.assertIsInstance(parsed, float)
                self.assertEqual(math.copysign(1.0, parsed), math.copysign(1.0, number))
        for number in (0, 1, -1, 2**63 - 1, -(2**63)):
            with self.subTest(number=number):
                text = self.assert_round_trip({"i": number})
                self.assertIsInstance(tomllib.loads(text)["i"], int)

    def test_bool_stays_bool(self) -> None:
        text = self.assert_round_trip({"t": True, "f": False, "one": 1, "zero": 0})
        parsed = tomllib.loads(text)
        self.assertIs(parsed["t"], True)
        self.assertIs(parsed["f"], False)
        self.assertIs(type(parsed["one"]), int)

    def test_randomised_structures_round_trip(self) -> None:
        rng = random.Random(20261110)
        for index in range(300):
            value = random_table(rng, 0)
            with self.subTest(index=index):
                self.assert_round_trip(value)


class DeterminismTests(unittest.TestCase):
    def test_same_input_same_bytes(self) -> None:
        first = tomlw.dumps(CONTOSO).encode("utf-8")
        for _ in range(3):
            self.assertEqual(tomlw.dumps(copy.deepcopy(CONTOSO)).encode("utf-8"), first)

    def test_insertion_order_does_not_matter(self) -> None:
        baseline = tomlw.dumps(CONTOSO)
        rng = random.Random(7)
        for _ in range(20):
            self.assertEqual(tomlw.dumps(reordered(CONTOSO, rng)), baseline)

    def test_layout_is_lf_sorted_and_newline_terminated(self) -> None:
        text = tomlw.dumps(CONTOSO)
        self.assertNotIn("\r", text)
        self.assertTrue(text.endswith("\n"))
        self.assertFalse(text.endswith("\n\n"))
        headers = [line for line in text.splitlines() if line.startswith("[")]
        self.assertEqual(headers, sorted(headers))
        self.assertEqual(len(headers), len([k for k, v in CONTOSO.items() if isinstance(v, dict)]))
        section: list[str] = []
        for line in text.splitlines() + ["["]:
            if line.startswith("[") or not line:
                keys = [entry.split(" = ", 1)[0] for entry in section]
                self.assertEqual(keys, sorted(keys))
                section = []
            else:
                section.append(line)

    def test_escaped_output_is_ascii_for_ascii_input(self) -> None:
        text = tomlw.dumps({"s": 'a\x00b\x7f\n"\\', "k\x01": True})
        self.assertTrue(text.isascii())
        self.assertEqual(tomllib.loads(text), {"s": 'a\x00b\x7f\n"\\', "k\x01": True})

    def test_table_mapping_types_are_normalised(self) -> None:
        proxy = MappingProxyType({"b": 1, "a": MappingProxyType({"x": "y"})})
        self.assertEqual(tomlw.dumps(proxy), tomlw.dumps({"a": {"x": "y"}, "b": 1}))


class RefusalTests(unittest.TestCase):
    def assert_refused(self, value: Any) -> None:
        with self.assertRaises(tomlw.TomlWriteError):
            tomlw.dumps(value)

    def test_none_nan_and_infinity(self) -> None:
        for bad in (None, math.nan, math.inf, -math.inf):
            with self.subTest(value=bad):
                self.assert_refused({"x": bad})
                self.assert_refused({"t": {"x": bad}})
                self.assert_refused({"arr": [1, bad]})

    def test_unsupported_types(self) -> None:
        class Colour(enum.Enum):
            RED = "red"

        class Flag(int):
            pass

        class Name(str):
            pass

        bad_values: list[Any] = [
            ("a", "b"),
            {"a", "b"},
            b"bytes",
            bytearray(b"x"),
            datetime.datetime(2026, 11, 10, 12, 0, 0),
            datetime.date(2026, 11, 10),
            datetime.time(12, 0),
            Colour.RED,
            Flag(1),
            Name("x"),
            1 + 2j,
            object(),
        ]
        for bad in bad_values:
            with self.subTest(value=repr(bad)):
                self.assert_refused({"x": bad})

    def test_nested_arrays_and_tables_in_arrays(self) -> None:
        self.assert_refused({"x": [[1, 2]]})
        self.assert_refused({"x": [{"a": 1}]})
        self.assert_refused({"x": [("a",)]})

    def test_bad_keys(self) -> None:
        self.assert_refused({1: "x"})
        self.assert_refused({"t": {None: "x"}})
        self.assert_refused({"\ud800": "x"})
        self.assert_refused({"ok": "lone \udfff surrogate"})

    def test_integer_range(self) -> None:
        self.assert_refused({"x": 2**63})
        self.assert_refused({"x": -(2**63) - 1})

    def test_top_level_must_be_mapping(self) -> None:
        for bad in (None, [], "x", 1, [("a", 1)]):
            with self.subTest(value=repr(bad)):
                self.assert_refused(bad)

    def test_cycles_and_excessive_depth(self) -> None:
        loop: dict[str, Any] = {}
        loop["self"] = loop
        self.assert_refused(loop)
        deep: dict[str, Any] = {}
        cursor = deep
        for _ in range(tomlw.MAX_DEPTH + 2):
            cursor["d"] = {}
            cursor = cursor["d"]
        self.assert_refused(deep)

    def test_shared_subtable_is_not_a_cycle(self) -> None:
        shared = {"x": 1}
        text = tomlw.dumps({"a": shared, "b": shared})
        self.assertEqual(tomllib.loads(text), {"a": {"x": 1}, "b": {"x": 1}})


if __name__ == "__main__":
    unittest.main()
