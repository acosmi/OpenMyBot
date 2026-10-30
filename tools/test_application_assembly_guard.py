#!/usr/bin/env python3
"""Positive and mutation checks for constructor ownership classification."""

import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from application_assembly_guard import GuardError, production_owners, repository_sources


class ApplicationAssemblyGuardTests(unittest.TestCase):
    def setUp(self):
        self.sources = {
            "src/assembly.rs": "fn make() { OpenBotApplication::new(store) }",
            "src/host.rs": "#[cfg(test)]\nmod tests;",
            "src/host/tests.rs": "fn fixture() { OpenBotApplication::new(fake) }",
        }

    def test_current_repository_has_one_production_owner(self):
        root = Path(__file__).resolve().parent.parent
        self.assertEqual(production_owners(repository_sources(root)), {
            "crates/openbot-infra/src/application_assembly.rs"
        })

    def test_explicit_test_module_is_excluded(self):
        self.assertEqual(production_owners(self.sources), {"src/assembly.rs"})

    def test_cfg_all_with_test_is_excluded_but_cfg_any_is_not(self):
        for attribute in [
            '#[cfg(all(test, feature = "desktop-local-runtime", target_os = "macos"))]',
            '#[cfg(all(feature = "desktop-local-runtime", test))]',
        ]:
            self.sources["src/host.rs"] = attribute + "\nmod tests;"
            self.assertEqual(production_owners(self.sources), {"src/assembly.rs"})
        for attribute in [
            '#[cfg(any(test, feature = "desktop-local-runtime"))]',
            '#[cfg(all(feature = "desktop-local-runtime", not(test)))]',
            '#[cfg(all(feature = "desktop-local-runtime", any(test, target_os = "macos")))]',
        ]:
            self.sources["src/host.rs"] = attribute + "\nmod tests;"
            self.assertIn("src/host/tests.rs", production_owners(self.sources))

    def test_filename_alone_does_not_exclude_constructor(self):
        self.sources["src/host.rs"] = "mod tests;"
        self.assertIn("src/host/tests.rs", production_owners(self.sources))
        del self.sources["src/host.rs"]
        self.assertIn("src/host/tests.rs", production_owners(self.sources))

    def test_inline_test_module_does_not_hide_later_production(self):
        self.sources["src/inline.rs"] = """
#[cfg(test)] mod tests { fn fake() { OpenBotApplication::new(fake) } }
fn actual() { OpenBotApplication::new(store) }
"""
        self.assertIn("src/inline.rs", production_owners(self.sources))
        self.sources["src/inline.rs"] = self.sources["src/inline.rs"].split("fn actual")[0]
        self.assertNotIn("src/inline.rs", production_owners(self.sources))

    def test_comments_and_strings_do_not_grant_test_exclusion(self):
        for annotation in ["// #[cfg(test)]", 'const NOTE: &str = "#[cfg(test)]";']:
            self.sources["src/host.rs"] = annotation + "\nmod tests;"
            self.assertIn("src/host/tests.rs", production_owners(self.sources))
        self.sources["src/extra.rs"] = '// OpenBotApplication::new(fake)\nconst X: &str = "OpenBotApplication::new(fake)";'
        self.assertNotIn("src/extra.rs", production_owners(self.sources))

    def test_path_attribute_and_production_alias_are_both_accounted(self):
        self.sources["src/host.rs"] = '#[cfg(test)]\n#[path = "host/tests.rs"]\nmod tests;'
        self.assertEqual(production_owners(self.sources), {"src/assembly.rs"})
        self.sources["src/other.rs"] = '#[path = "host/tests.rs"]\nmod actual;'
        self.assertIn("src/host/tests.rs", production_owners(self.sources))

    def test_production_include_cancels_test_exclusion(self):
        self.sources["src/other.rs"] = 'include!("host/tests.rs");'
        self.assertIn("src/host/tests.rs", production_owners(self.sources))

    def test_computed_include_is_not_silently_ignored(self):
        self.sources["src/other.rs"] = 'include!(concat!("host", "/tests.rs"));'
        with self.assertRaises(GuardError):
            production_owners(self.sources)

    def test_nested_test_files_are_excluded_but_production_reference_wins(self):
        self.sources["src/host/tests.rs"] += "\nmod helper;"
        self.sources["src/host/tests/helper.rs"] = "fn fixture() { OpenBotApplication::new(fake) }"
        self.assertEqual(production_owners(self.sources), {"src/assembly.rs"})
        self.sources["src/other.rs"] = '#[path = "host/tests/helper.rs"]\nmod actual;'
        self.assertIn("src/host/tests/helper.rs", production_owners(self.sources))

    def test_real_extra_constructor_remains_rejected_by_owner_set(self):
        self.sources["src/product.rs"] = "fn make() { OpenBotApplication :: new(store) }"
        self.assertEqual(production_owners(self.sources), {"src/assembly.rs", "src/product.rs"})


if __name__ == "__main__":
    unittest.main()
