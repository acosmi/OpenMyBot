"""Regression tests for accidental publication of local material."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('guard', Path(__file__).with_name('repository_guard.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class PublicationGuardTests(unittest.TestCase):
    def test_private_paths_and_unreviewed_documents_are_rejected(self):
        for path in ['docs/notes.md', 'grok-bot/src/index.ts', 'crates/x/implementation.md', 'crates/x/.env', '.local-private/backup.tar.gz', 'artifacts/logo.zip', 'crates/x/node_modules/a.js', 'openmybot/README-copy.md', 'openmybot/README.zh-CN-copy.md', 'openmybot/compat/internal.md', 'openmybot/hosts/internal.md']:
            with self.subTest(path=path):
                self.assertIsNotNone(guard.forbidden(path))
        for path in ['README.md', 'IMPLEMENTATION_LEDGER.md', 'Cargo.lock', 'crates/wrokbot-ui/assets/brand/wrok-bot-motion.gif', 'openmybot/README.md', 'openmybot/README.zh-CN.md', 'openmybot/compat/README.md', 'openmybot/hosts/README.md']:
            self.assertIsNone(guard.forbidden(path))

    def test_implementation_ledger_allowlist_is_exact(self):
        for path in [
            'IMPLEMENTATION-LEDGER.md',
            'IMPLEMENTATION_LEDGER-copy.md',
            'OTHER_LEDGER.md',
            'docs/IMPLEMENTATION_LEDGER.md',
            'docs/history-ledger.md',
        ]:
            with self.subTest(path=path):
                self.assertIsNotNone(guard.forbidden(path))

    def test_ui_rename_history_allowlist_is_exact_and_does_not_open_adjacent_docs(self):
        reviewed_suffixes = [
            'assets/fonts/LICENSE.txt',
            'assets/notices/markdown/README.txt',
            'assets/notices/markdown/SublimeText_PowerShell_LICENSE.txt',
            'assets/notices/markdown/guille_sublime-kotlin_LICENSE.md',
            'design/markdown/PROVENANCE.md',
            'locales/GLOSSARY.md',
        ]
        for crate in ['openbot-ui', 'wrokbot-ui']:
            for suffix in reviewed_suffixes:
                path = f'crates/{crate}/{suffix}'
                with self.subTest(path=path):
                    self.assertIsNone(guard.forbidden(path))
            for path in [
                f'crates/{crate}/docs/README.md',
                f'crates/{crate}/design/markdown/PROVENANCE-copy.md',
                f'crates/{crate}/locales/internal.md',
            ]:
                with self.subTest(path=path):
                    self.assertIsNotNone(guard.forbidden(path))

        limits = guard.POLICY['file_size_limits']
        expected = 31_457_280
        self.assertEqual(
            limits['crates/openbot-ui/assets/brand/wrok-bot-logo-1024.gif'], expected
        )
        self.assertEqual(
            limits['crates/wrokbot-ui/assets/brand/wrok-bot-logo-1024.gif'], expected
        )
        self.assertNotIn('crates/openbot-ui/assets/brand/other.gif', limits)
        self.assertNotIn('crates/wrokbot-ui/assets/brand/other.gif', limits)

    def test_content_rules_preserve_public_status_but_block_internal_plans(self):
        self.assertIsNotNone(guard.content_reason('README.md', '实施方案：内部任务分配'.encode()))
        self.assertIsNone(guard.content_reason('README.md', '当前进度：macOS 首版开发中；预计完成日期待确认。'.encode()))

    def test_staged_content_is_scanned_even_when_worktree_is_cleaned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.init(root)
            (root / 'README.md').write_text('实施方案：内部内容')
            self.run_git(root, 'add', 'README.md')
            (root / 'README.md').write_text('Wrok Bot')
            with self.assertRaisesRegex(RuntimeError, 'internal implementation'):
                guard.inspect(root=root)

    def test_staged_implementation_ledger_still_enforces_private_content_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.init(root)
            ledger = root / 'IMPLEMENTATION_LEDGER.md'
            ledger.write_text('实施方案：内部任务分配')
            self.run_git(root, 'add', 'IMPLEMENTATION_LEDGER.md')
            with self.assertRaisesRegex(RuntimeError, 'internal implementation'):
                guard.inspect(root=root)

            ledger.write_text('# Implementation Ledger\n\nCurrent status: complete.\n')
            self.run_git(root, 'add', 'IMPLEMENTATION_LEDGER.md')
            files = guard.inspect(root=root)
            self.assertEqual(files, [
                ('IMPLEMENTATION_LEDGER.md', b'# Implementation Ledger\n\nCurrent status: complete.\n'),
            ])

    def test_deleted_private_file_still_blocks_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.init(root)
            (root / 'docs').mkdir()
            (root / 'docs/notes.md').write_text('private')
            self.run_git(root, 'add', 'docs/notes.md')
            self.run_git(root, 'commit', '-qm', 'initial')
            self.run_git(root, 'rm', '-q', 'docs/notes.md')
            (root / 'README.md').write_text('Wrok Bot')
            self.run_git(root, 'add', 'README.md')
            self.run_git(root, 'commit', '-qm', 'remove private file')
            with patch.object(guard, 'scan'):
                with self.assertRaisesRegex(RuntimeError, 'docs/notes.md'):
                    guard.check_history(['HEAD'], root)

    def test_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.init(root)
            (root / 'README.md').symlink_to('/etc/passwd')
            self.run_git(root, 'add', 'README.md')
            with self.assertRaisesRegex(RuntimeError, 'symlink'):
                guard.inspect(root=root)

    def test_absolute_hook_blocks_legacy_history_from_another_worktree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.init(root)
            (root / 'docs').mkdir()
            (root / 'docs/notes.md').write_text('private')
            self.run_git(root, 'add', 'docs/notes.md')
            self.run_git(root, 'commit', '-qm', 'local history')
            oid = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root).decode().strip()
            hook = Path(__file__).resolve().parents[1] / '.githooks/pre-push'
            result = subprocess.run([str(hook), 'origin', 'https://github.com/acosmi/wrokbot.git'],
                                    cwd=root, input=f'refs/heads/main {oid} refs/heads/main {"0" * 40}\n',
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('docs/notes.md', result.stderr)

    @staticmethod
    def run_git(root, *args):
        subprocess.run(['git', *args], cwd=root, check=True, capture_output=True)

    def init(self, root):
        self.run_git(root, 'init', '-q', '-b', 'main')
        self.run_git(root, 'config', 'user.name', 'Guard Test')
        self.run_git(root, 'config', 'user.email', 'guard@example.invalid')
        self.run_git(root, 'config', 'commit.gpgsign', 'false')
        self.run_git(root, 'config', 'core.hooksPath', '/dev/null')


if __name__ == '__main__':
    unittest.main()
