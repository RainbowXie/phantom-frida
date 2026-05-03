"""Invariant tests for patches.py.

Build-time correctness checks for the patch tables that drive
phantom-frida's source-level rename pipeline. They run in milliseconds
and have no external dependencies — meant to gate every workflow run
before the long Frida clone + build kicks off.

Run:
    python3 -m unittest discover -s tests
"""
import os
import sys
import unittest

# Make `import patches` work whether tests are launched from repo root
# or from the tests/ directory itself.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patches import (  # noqa: E402
    SELINUX_PATCHES,
    get_binary_patches,
    get_binary_string_patches,
    get_internal_patches,
    get_rollback_patches,
    get_source_patches,
    get_targeted_patches,
    get_temp_path_patches,
    get_transport_patches,
)


CUSTOM_NAME = "ajeossida"
CAP_NAME = "Ajeossida"


class SourcePatches(unittest.TestCase):
    def setUp(self):
        self.patches = get_source_patches(CUSTOM_NAME, CAP_NAME)

    def test_nonempty_pairs(self):
        for old, new in self.patches:
            self.assertTrue(old, "empty `old` literal")
            self.assertTrue(new, "empty `new` literal")
            self.assertNotEqual(old, new, f"no-op rule: {old!r}")

    def test_no_duplicate_old(self):
        olds = [old for old, _ in self.patches]
        seen, dups = set(), []
        for o in olds:
            if o in seen:
                dups.append(o)
            seen.add(o)
        self.assertEqual(dups, [], f"duplicate `old` literals: {dups}")

    def test_no_self_referential_chains(self):
        """A patch's `new` must not equal another patch's `old` — that would
        produce non-deterministic behaviour depending on iteration order."""
        olds = {old for old, _ in self.patches}
        chains = [(old, new) for old, new in self.patches if new in olds]
        self.assertEqual(chains, [], f"chained rewrites: {chains}")

    def test_short5_path_block_present_for_long_names(self):
        marker = '"/frida/runtime/"'
        self.assertIn(marker, [o for o, _ in self.patches],
                      "expected /frida/runtime/ patch when name >= 5 chars")

    def test_short5_path_block_disabled_for_short_names(self):
        ps = get_source_patches("xyz", "Xyz")
        olds = [o for o, _ in ps]
        for marker in ('"/frida/runtime/"', '"/frida/capstone "',
                       '"-isystem /frida "', '"frida/runtime"'):
            self.assertNotIn(
                marker, olds,
                f"name='xyz' (<5 chars) should skip /frida/ block, "
                f"but found {marker!r}",
            )

    def test_short5_keeps_seven_byte_prefix(self):
        """`/frida/` is 7 bytes; the rewrite must stay 7 bytes so
        gumcmodule.c:678 `name += 7;` stays valid."""
        for old, new in self.patches:
            if old == '"/frida/runtime/"':
                # Extract the bracketed prefix from `"/<short5>/runtime/"`.
                prefix = new.split("runtime")[0]  # `"/<short5>/`
                # Strip leading `"`.
                self.assertEqual(prefix[0], '"')
                self.assertEqual(len(prefix) - 1, 7,
                                 f"prefix not 7 bytes: {prefix!r}")
                return
        self.fail("/frida/runtime/ patch not found")


class BinaryPatches(unittest.TestCase):
    def test_thread_name_patches_same_length(self):
        for old_hex, new_hex, desc in get_binary_patches():
            self.assertEqual(
                len(bytes.fromhex(old_hex)), len(bytes.fromhex(new_hex)),
                f"length mismatch in binary patch: {desc}",
            )

    def test_string_sweep_patches_same_length(self):
        for old_hex, new_hex, desc in get_binary_string_patches(CUSTOM_NAME):
            self.assertEqual(
                len(bytes.fromhex(old_hex)), len(bytes.fromhex(new_hex)),
                f"length mismatch in string sweep: {desc}",
            )

    def test_pascalcase_sweep_covers_full_alphabet(self):
        descriptions = {desc for _, _, desc in get_binary_string_patches(CUSTOM_NAME)}
        for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            self.assertIn(
                f'residual "Frida{c}" -> "{CAP_NAME[:5]}{c}"',
                descriptions,
                f"missing PascalCase pattern for Frida{c}",
            )

    def test_pascalcase_sweep_skipped_for_short_name(self):
        ps = get_binary_string_patches("xyz")
        for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            for _, _, desc in ps:
                self.assertNotIn(f"Frida{c}", desc,
                                 f"name='xyz' (<5 chars) should skip PascalCase")

    def test_no_zero_byte_old_pattern(self):
        for old_hex, _, desc in get_binary_string_patches(CUSTOM_NAME):
            old = bytes.fromhex(old_hex)
            self.assertNotEqual(old, b"", f"empty old pattern: {desc}")
            self.assertGreaterEqual(
                len(old), 4,
                f"sweep pattern too short, risk of false positive: {desc}",
            )


class RollbackPatches(unittest.TestCase):
    def test_rollback_pairs_swap_directions(self):
        """`old` must contain the custom name; `new` must restore frida-."""
        for old, new in get_rollback_patches(CUSTOM_NAME):
            self.assertIn(CUSTOM_NAME, old, f"rollback old missing custom name: {old}")
            self.assertIn("frida-", new, f"rollback new not restoring frida-: {new}")


class TargetedPatches(unittest.TestCase):
    def test_known_targets_nonempty(self):
        for t in ("server_meson", "compat_build", "core_meson",
                  "gadget_meson", "agent_meson"):
            self.assertGreater(
                len(get_targeted_patches(CUSTOM_NAME, CAP_NAME, t)), 0,
                f"target {t!r} returned no patches",
            )

    def test_unknown_target_empty(self):
        self.assertEqual(
            get_targeted_patches(CUSTOM_NAME, CAP_NAME, "no_such_target"),
            [],
        )


class ExtendedPatches(unittest.TestCase):
    def test_internal_patches_nonempty(self):
        self.assertGreater(len(get_internal_patches(CUSTOM_NAME, CAP_NAME)), 0)

    def test_temp_path_patches_nonempty(self):
        self.assertGreater(len(get_temp_path_patches(CUSTOM_NAME)), 0)

    def test_transport_patches_callable(self):
        # Transport block is intentionally returned as a list; can be empty
        # in some Frida versions. Just assert the call doesn't raise and
        # returns a list of (str, str) tuples.
        result = get_transport_patches(CUSTOM_NAME)
        self.assertIsInstance(result, list)
        for item in result:
            self.assertEqual(len(item), 2)
            self.assertIsInstance(item[0], str)
            self.assertIsInstance(item[1], str)

    def test_selinux_block_targets_frida_only(self):
        for old, new in SELINUX_PATCHES(CUSTOM_NAME):
            self.assertIn("frida", old)
            self.assertIn(CUSTOM_NAME, new)


if __name__ == "__main__":
    unittest.main(verbosity=2)
