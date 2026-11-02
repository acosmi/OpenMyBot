#!/usr/bin/env python3
"""Mutation tests for the Desktop Local staged-shutdown guard."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

from tauri_background_assembly_guard import GuardError, check_source  # noqa: E402


SOURCE_PATH = ROOT / "crates/openbot-desktop/src/tauri_background.rs"


def replace_once(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise AssertionError(f"mutation anchor count for {old!r}: {count}")
    return source.replace(old, new, 1)


def replace_after(source: str, marker: str, old: str, new: str) -> str:
    before, separator, after = source.partition(marker)
    if not separator:
        raise AssertionError(f"missing mutation marker {marker!r}")
    return before + separator + replace_once(after, old, new)



AUTHORITY = "    let authority_ok = capturing || owner.lifecycle.shutdown_authority().is_ok();\n"
CAPTURING_OFF = "    let capturing = false;\n"
CAPTURE_ENTRY = "        let result = capture::run_normal_exit_capture(&mut job, ready).await;\n"
CAPTURE_RETURN = "        return;\n    }\n    let DesktopLocalClosingJob {"
STARTUP_OK = "        startup_ok: authority_ok && state_install_ok,"
SPAWN = "    tauri::async_runtime::spawn(run_owned_local_closing_job(job));\n"
DEADLINE = "let deadline = started + crate::cancel::SHUTDOWN_DEADLINE;"
INNER_JOIN = """        let (transport, agent, assembly, ()): (
            _,
            Option<AgentCloseObservation>,
            Option<AssemblyCloseObservation>,
            (),
        ) = tokio::join!("""
STAGE_RESULT = "        (transport.within_deadline, agent, assembly)\n"
OUTER_JOIN = "    let (non_database, drain) = tokio::join!("
TIMEOUT = "tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), non_database)"
DATABASE = """    let database_result = match owner.data_plane.take() {
        Some(data_plane) => data_plane.shutdown().await,
        None => Err((
            DesktopLocalCompositionError::SidecarShutdown,
            Err(crate::postgres_sidecar::SidecarOutcome::Unknown),
            crate::desktop_local_bootstrap::SqlDriverOutcome::Unknown,
        )),
    };
"""
SUCCESS = "        startup_ok && observations_ok && non_database_ok && drain_in_deadline && database_ok,"
REPLY = """    let _observer_received = reply.send(if succeeded {
        Ok(())
    } else {
        Err(DesktopLocalRuntimeError::Shutdown)
    });"""
PROJECTION = """    let non_database_ok = match &non_database {
        Ok((true, ..)) => {
            observe_exit("non_database", "ok");
            true
        }
        Ok((false, ..)) => {
            observe_exit("non_database", "failed");
            false
        }
        Err(_) => {
            observe_exit("non_database", "timed_out");
            false
        }
    };"""
HELPER = "async fn finish_shutdown_stages<N, D, E>("
HELPER_NON_DATABASE = """    let (non_database_ok, original) =
        match tokio::time::timeout(non_database_window, non_database).await {"""
HELPER_DATABASE = "    let database = database.await;"
STARTED = "    let started = Instant::now();\n    " + DEADLINE + "\n"
FINISH = "    let succeeded = completion.finish(\n"
STAGE_START = "    let non_database = async {\n"
STAGE_END = STAGE_RESULT + "    };\n"


def stage_block(source: str) -> str:
    start = source.index(STAGE_START)
    return source[start:source.index(STAGE_END, start) + len(STAGE_END)]


def dead_stage_before_join(source: str) -> str:
    block = stage_block(source)
    dead = "    if false {\n" + block + "    }\n"
    return replace_once(source, block, "    let non_database = async { (true, None, None) };\n" + dead)


def dead_stage_after_database(source: str) -> str:
    block = stage_block(source)
    source = replace_once(source, block, "    let non_database = async { (true, None, None) };\n")
    return replace_once(source, FINISH, "    if false {\n" + block + "    }\n" + FINISH)


# Mutations of the production closing structure, each of which must be rejected.
REVIEWED_MUTATIONS = {
    "M01 authority removed": [(AUTHORITY, "    let authority_ok = true;\n")],
    "M02 authority conditional": [
        (
            AUTHORITY,
            "    let authority_ok = if completion.is_some() {"
            " owner.lifecycle.shutdown_authority().is_ok() } else { true };\n",
        )
    ],
    "M03 authority unchecked": [
        (
            AUTHORITY,
            "    let authority_ok = { let _ = owner.lifecycle.shutdown_authority(); true };\n",
        )
    ],
    "M04 authority not in startup_ok": [(STARTUP_OK, "        startup_ok: state_install_ok,")],
    "M05 authority after spawn": [(AUTHORITY, ""), (SPAWN, SPAWN + AUTHORITY)],
    "M06 deadline not shared": [
        (DEADLINE, "let deadline = started + Duration::from_secs(60);")
    ],
    "M07 branch dropped": [
        (
            "            owner.lifecycle.wait_local_confirmation_stopped(),\n        );",
            "        );",
        ),
        (
            INNER_JOIN,
            "        let (transport, agent, assembly): (_, Option<AgentCloseObservation>, "
            "Option<AssemblyCloseObservation>) = tokio::join!(",
        ),
    ],
    "M08 serial before join": [
        (
            INNER_JOIN,
            "        owner.lifecycle.wait_local_confirmation_stopped().await;\n" + INNER_JOIN,
        )
    ],
    "M09 transport not gating": [
        (STAGE_RESULT, "        let _ = transport;\n        (true, agent, assembly)\n")
    ],
    "M10 timeout false as success": [
        (
            PROJECTION,
            PROJECTION.replace(
                '"failed");\n            false', '"failed");\n            true'
            ),
        )
    ],
    "M11 timeout widened": [
        (
            TIMEOUT,
            "tokio::time::timeout_at(tokio::time::Instant::from_std("
            "deadline + Duration::from_secs(1)), non_database)",
        )
    ],
    "M12 database conditional": [
        (
            DATABASE,
            "    let database_result = if non_database_ok {\n"
            + DATABASE.replace("    let database_result = ", "").replace("};\n", "}\n")
            + "    } else {\n        Err((DesktopLocalCompositionError::SidecarShutdown, "
            "Err(crate::postgres_sidecar::SidecarOutcome::Unknown), "
            "crate::desktop_local_bootstrap::SqlDriverOutcome::Unknown))\n    };\n",
        )
    ],
    "M13 early return before database": [
        (
            "    if !drain_in_deadline {\n",
            "    if !non_database_ok {\n        return;\n    }\n    if !drain_in_deadline {\n",
        )
    ],
    "M14 database result ignored": [
        (
            "    let database_ok = database_result.is_ok();",
            "    let database_ok = { let _ = &database_result; true };",
        )
    ],
    "M15 success without database": [
        (SUCCESS, "        startup_ok && observations_ok && non_database_ok && drain_in_deadline,")
    ],
    "M16 failure reported as Ok": [
        (REPLY, "    let _observer_received = reply.send(Ok(()));")
    ],
    "M17 completion widens": [
        (
            "        let succeeded = succeeded && observed;",
            "        let succeeded = succeeded || observed;",
        )
    ],
    "M18 data plane in non-database": [
        (
            "    let non_database = async {\n",
            "    let non_database = async {\n        let _plane = owner.data_plane.take();\n",
        )
    ],
    "M19 start_closing bypass": [
        (
            "        start_owned_local_closing_job(self, completion)\n",
            "        start_owned_local_closing_job(self, None)\n",
        )
    ],
    "M20 helper success widened": [
        (
            "    let outcome = if non_database_ok && database_ok {\n        Ok(())",
            "    let outcome = if non_database_ok || database_ok {\n        Ok(())",
        )
    ],
    # Review v1: stage results are identified by binding position, not by name.
    "M21 database result shadowed": [
        (FINISH, "    let database_ok = database_ok || true;\n" + FINISH)
    ],
    "M22 non-database result shadowed": [
        (FINISH, "    let non_database_ok = non_database_ok || true;\n" + FINISH)
    ],
    "M23 startup result shadowed": [(FINISH, "    let startup_ok = startup_ok || true;\n" + FINISH)],
    "M24 database result rebound after alias": [
        (FINISH, "    let db = database_ok;\n    let database_ok = db || true;\n" + FINISH)
    ],
    "M25 authority result shadowed": [
        (AUTHORITY, AUTHORITY + "    let authority_ok = authority_ok || true;\n")
    ],
    "M26 dead same-name stage before the join": [dead_stage_before_join],
    "M27 dead same-name stage after the database stage": [dead_stage_after_database],
    "M28 timeout result rebound before projection": [
        (
            "    let non_database_ok = match &non_database {\n",
            "    let non_database = Ok::<_, tokio::time::error::Elapsed>((true, None, None));\n"
            "    let non_database_ok = match &non_database {\n",
        )
    ],
    "M29 transport result rebound after the join": [
        (STAGE_RESULT, "        let transport = FakeTransportStop { within_deadline: true };\n" + STAGE_RESULT)
    ],
    # Review v1: the shared deadline is the verbatim started + SHUTDOWN_DEADLINE binding.
    "M30 deadline prefix widened": [
        (
            DEADLINE,
            "let deadline = started + Duration::from_secs(3600) + crate::cancel::SHUTDOWN_DEADLINE;",
        )
    ],
    "M31 start instant widened": [
        (
            STARTED,
            "    let started = Instant::now() + Duration::from_secs(3600);\n    " + DEADLINE + "\n",
        )
    ],
    "M32 deadline rebound": [
        (STARTED, STARTED + "    let deadline = deadline + Duration::from_secs(3600);\n")
    ],
    "M33 deadline rebound through an alias": [
        (
            STARTED,
            STARTED
            + "    let widened = deadline;\n"
            + "    let deadline = widened + Duration::from_secs(3600);\n",
        )
    ],
    # Review v2: the timeout result name cannot be rebound at all, and macro call groups are
    # transparent to the enclosing scope.
    "M34 timeout result replaced through an alias": [
        (
            OUTER_JOIN,
            "    let fake_result = Ok::<_, tokio::time::error::Elapsed>((true, None, None));\n"
            + OUTER_JOIN,
        ),
        (PROJECTION, "    let non_database = fake_result;\n" + PROJECTION),
    ],
    "M35 database result shadowed inside a statement macro": [
        (
            "async fn run_owned_local_closing_job(",
            "macro_rules! stmts { ($($t:tt)*) => { $($t)* }; }\n\n"
            "async fn run_owned_local_closing_job(",
        ),
        (FINISH, "    stmts! { let database_ok = true; }\n" + FINISH),
    ],
    # Review v3: braces nested inside any macro call group stay transparent, and the timeout
    # projection must stay at the top level of the closing job.
    "M36 database result shadowed through a brace-stripping macro": [
        (
            "async fn run_owned_local_closing_job(",
            "macro_rules! strip { ({ $($t:tt)* }) => { $($t)* }; }\n\n"
            "async fn run_owned_local_closing_job(",
        ),
        (FINISH, "    strip!({ let database_ok = true; });\n" + FINISH),
    ],
    "M37 projection hidden in a block macro behind an outer fake": [
        (
            "async fn run_owned_local_closing_job(",
            "macro_rules! blk { ($($t:tt)*) => {{ $($t)* }}; }\n\n"
            "async fn run_owned_local_closing_job(",
        ),
        (PROJECTION, "    let non_database_ok = true;\n    blk! {\n" + PROJECTION + "\n    }"),
    ],
}


class AssemblyGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE_PATH.read_text(encoding="utf-8")

    def assert_rejected(self, source: str) -> None:
        with self.assertRaises(GuardError):
            check_source(source)

    def test_current_production_source_passes(self) -> None:
        check_source(self.source)

    def test_comment_only_change_is_accepted(self) -> None:
        check_source(
            replace_once(
                self.source,
                "    // The data plane stays in owner, outside all deadline-limited subfutures.\n",
                "    // reviewed comment\n"
                "    // The data plane stays in owner, outside all deadline-limited subfutures.\n",
            )
        )

    def test_reviewed_mutations_are_rejected(self) -> None:
        for name, edits in REVIEWED_MUTATIONS.items():
            with self.subTest(mutation=name):
                source = self.source
                for edit in edits:
                    source = edit(source) if callable(edit) else replace_once(source, *edit)
                self.assert_rejected(source)

    def test_local_aliases_comments_and_join_branch_order_are_accepted(self) -> None:
        source = replace_once(
            self.source,
            "let agent_host = owner.agent_host.take();",
            "let agent_worker = owner.agent_host.take();",
        )
        source = replace_once(
            source,
            "let agent_started = agent_host.as_ref().map(DesktopAgentHost::agent_started);",
            "let agent_started = agent_worker.as_ref().map(DesktopAgentHost::agent_started);",
        )
        source = replace_once(source, "match agent_host {", "match agent_worker {")
        source = replace_once(source, "Some(mut host) => {", "Some(mut host_alias) => {")
        source = replace_once(
            source,
            "let result = host.stop_for_capture().await;",
            "let result = host_alias.stop_for_capture().await;",
        )
        source = replace_once(source, "drop(host);", "drop(host_alias);")
        original = INNER_JOIN + """
            owner.transport.shutdown(),
            async {
                match agent_worker {
                    Some(mut host_alias) => {
                        let result = host_alias.stop_for_capture().await;
                        let observed_ns = close_observed_ns();
                        drop(host_alias);
                        Some((
                            agent_started.expect("the same original agent host"),
                            result,
                            observed_ns,
                        ))
                    }
                    None => None,
                }
            },
            async {
                match assembly {
                    Some(mut assembly) => {
                        let result = assembly.stop_for_capture().await;
                        let observed_ns = close_observed_ns();
                        drop(assembly);
                        Some((result, observed_ns))
                    }
                    None => None,
                }
            },
            owner.lifecycle.wait_local_confirmation_stopped(),
        );"""
        reordered = """        let ((), assembly, agent, transport): (
            (), Option<AssemblyCloseObservation>, Option<AgentCloseObservation>, _,
        ) = tokio::join!(
            /* native confirmation branch may be listed first */
            owner.lifecycle.wait_local_confirmation_stopped(),
            async {
                match assembly {
                    Some(mut assembly_alias) => {
                        let result = assembly_alias.stop_for_capture().await;
                        let observed_ns = close_observed_ns();
                        drop(assembly_alias);
                        Some((result, observed_ns))
                    }
                    None => None,
                }
            },
            async {
                match agent_worker {
                    Some(mut host_alias) => {
                        let result = host_alias.stop_for_capture().await;
                        let observed_ns = close_observed_ns();
                        drop(host_alias);
                        Some((agent_started.expect("the same original agent host"), result, observed_ns))
                    }
                    None => None,
                }
            },
            owner.transport.shutdown(),
        );"""
        check_source(replace_once(source, original, reordered))

    def test_stage_future_and_deadline_aliases_are_accepted(self) -> None:
        source = replace_once(
            self.source,
            OUTER_JOIN,
            "    let non_database_alias = non_database;\n"
            "    let deadline_alias = deadline;\n" + OUTER_JOIN,
        )
        source = replace_once(
            source,
            TIMEOUT,
            "tokio::time::timeout_at(tokio::time::Instant::from_std(deadline_alias), "
            "non_database_alias)",
        )
        source = replace_after(
            source,
            HELPER,
            HELPER_NON_DATABASE,
            """    let window_alias = non_database_window;
    let non_database_alias = non_database;
    let (non_database_ok, original) =
        match tokio::time::timeout(window_alias, non_database_alias).await {""",
        )
        source = replace_after(
            source,
            HELPER,
            HELPER_DATABASE,
            "    let database_alias = database;\n    let database = database_alias.await;",
        )
        check_source(source)

    def test_stage_result_aliases_are_accepted(self) -> None:
        source = replace_once(
            self.source,
            STAGE_RESULT,
            "        let transport_result_alias = transport.within_deadline;\n"
            "        (transport_result_alias, agent, assembly)\n",
        )
        source = replace_once(
            source, AUTHORITY, AUTHORITY + "    let authority_result_alias = authority_ok;\n"
        )
        source = replace_once(
            source, STARTUP_OK, "        startup_ok: authority_result_alias && state_install_ok,"
        )
        source = replace_once(
            source,
            SUCCESS,
            "        startup_ok && observations_ok && non_database_ok && drain_in_deadline"
            " && database_result_alias,",
        )
        source = replace_once(
            source,
            "    let succeeded = completion.finish(\n",
            "    let database_result_alias = database_ok;\n    let succeeded = completion.finish(\n",
        )
        source = replace_after(
            source,
            HELPER,
            "    let outcome = if non_database_ok && database_ok {",
            """    let non_database_result_alias = non_database_ok;
    let database_result_alias = database_ok;
    let outcome = if database_result_alias && non_database_result_alias {""",
        )
        check_source(source)

    def test_each_required_concurrent_stop_is_required_in_the_production_join(self) -> None:
        mutations = [
            ("let result = host.stop_for_capture().await;", "let result = Ok(());"),
            (
                "                        let result = assembly.stop_for_capture().await;",
                "                        let result = Ok(());",
            ),
            (
                "owner.transport.shutdown(),",
                "async { core::future::ready(()).await },",
            ),
            (
                "owner.lifecycle.wait_local_confirmation_stopped(),",
                "async { core::future::ready(()).await },",
            ),
        ]
        for old, new in mutations:
            with self.subTest(removed=old):
                self.assert_rejected(replace_once(self.source, old, new))

    def test_comment_or_test_only_stop_cannot_replace_production_agent_stop(self) -> None:
        source = replace_once(
            self.source,
            "let result = host.stop_for_capture().await;",
            "// let result = host.stop_for_capture().await;\n                        let result = Ok(());",
        )
        source += "\n#[cfg(test)] mod fake_guard_evidence { fn only_test() { agent_host.stop_for_capture(); } }\n"
        self.assert_rejected(source)

    def test_async_stop_method_names_without_await_are_not_evidence(self) -> None:
        for old, new in [
            ("let result = host.stop_for_capture().await;", "let result = host.stop_for_capture();"),
            (
                "                        let result = assembly.stop_for_capture().await;",
                "                        let result = assembly.stop_for_capture();",
            ),
        ]:
            with self.subTest(unpolled=old):
                self.assert_rejected(replace_once(self.source, old, new))
        self.assert_rejected(
            replace_once(
                self.source,
                "let result = host.stop_for_capture().await;",
                "let result = async { host.stop_for_capture().await };",
            )
        )
        self.assert_rejected(
            replace_once(
                self.source,
                "let result = host.stop_for_capture().await;",
                "return None; let result = host.stop_for_capture().await;",
            )
        )

    def test_authority_must_be_revoked_before_join_without_serial_await(self) -> None:
        self.assert_rejected(replace_once(self.source, AUTHORITY, "    let authority_ok = true;\n"))
        self.assert_rejected(
            replace_once(self.source, STARTUP_OK, "        startup_ok: state_install_ok,")
        )
        self.assert_rejected(
            replace_once(
                self.source,
                INNER_JOIN,
                "        owner.transport.shutdown().await;\n" + INNER_JOIN,
            )
        )

    def test_database_cannot_run_before_or_only_after_successful_non_database_stage(self) -> None:
        pg_first = replace_once(self.source, DATABASE, "")
        pg_first = replace_once(pg_first, OUTER_JOIN, DATABASE + OUTER_JOIN)
        self.assert_rejected(pg_first)
        self.assert_rejected(
            replace_once(
                self.source,
                DATABASE,
                "    let database_result = if non_database_ok {\n"
                + DATABASE.replace("    let database_result = ", "").replace("};\n", "}\n")
                + "    } else {\n        Err((DesktopLocalCompositionError::SidecarShutdown, "
                "Err(crate::postgres_sidecar::SidecarOutcome::Unknown), "
                "crate::desktop_local_bootstrap::SqlDriverOutcome::Unknown))\n    };\n",
            )
        )
        marker = HELPER
        pg_first = replace_after(
            self.source,
            marker,
            HELPER_DATABASE + "\n",
            "",
        )
        pg_first = replace_after(
            pg_first,
            marker,
            HELPER_NON_DATABASE,
            HELPER_DATABASE + "\n" + HELPER_NON_DATABASE,
        )
        self.assert_rejected(pg_first)
        self.assert_rejected(
            replace_after(
                self.source,
                marker,
                HELPER_DATABASE,
                "    let database = if non_database_ok { database.await } else { unreachable!() };",
            )
        )

    def test_shared_deadline_and_real_owner_hand_off_are_required(self) -> None:
        self.assert_rejected(
            replace_once(self.source, DEADLINE, "let deadline = started + Duration::from_secs(60);")
        )
        self.assert_rejected(
            replace_once(
                self.source,
                DEADLINE,
                "let deadline = started + crate::cancel::SHUTDOWN_DEADLINE * 100;",
            )
        )
        self.assert_rejected(
            replace_once(
                self.source,
                "        start_owned_local_closing_job(self, completion)\n",
                "        fake_start_owned_local_closing_job(self, completion)\n",
            )
        )
        self.assert_rejected(
            replace_once(
                self.source,
                SPAWN,
                "    tauri::async_runtime::spawn(fake_closing_job(job));\n",
            )
        )
        self.assert_rejected(replace_once(self.source, TIMEOUT, "async { Ok(non_database.await) }"))
        self.assert_rejected(
            replace_after(
                self.source,
                HELPER,
                "tokio::time::timeout(non_database_window, non_database).await",
                "non_database.await",
            )
        )

    def test_any_stage_failure_must_remain_a_shutdown_failure(self) -> None:
        self.assert_rejected(
            replace_once(self.source, REPLY, "    let _observer_received = reply.send(Ok(()));")
        )
        self.assert_rejected(
            replace_once(
                self.source,
                SUCCESS,
                "        startup_ok && observations_ok && non_database_ok && drain_in_deadline,",
            )
        )
        self.assert_rejected(
            replace_once(
                self.source,
                "    if !drain_in_deadline {\n",
                "    if !non_database_ok {\n        return;\n    }\n    if !drain_in_deadline {\n",
            )
        )
        self.assert_rejected(
            replace_after(
                self.source,
                HELPER,
                "    } else {\n        Err(DesktopLocalRuntimeError::Shutdown)\n    }",
                "    } else {\n        Ok(())\n    }",
            )
        )
        self.assert_rejected(
            replace_after(
                self.source,
                HELPER,
                "if non_database_ok && database_ok",
                "if !non_database_ok && !database_ok",
            )
        )
        self.assert_rejected(
            replace_after(
                self.source,
                HELPER,
                """    let outcome = if non_database_ok && database_ok {
        Ok(())
    } else {
        Err(DesktopLocalRuntimeError::Shutdown)
    };""",
                """    let _ignored = if non_database_ok && database_ok {
        Ok(())
    } else {
        Err(DesktopLocalRuntimeError::Shutdown)
    };
    let outcome = Ok(());""",
            )
        )
        self.assert_rejected(
            replace_after(
                self.source,
                HELPER,
                HELPER_DATABASE,
                """    if !non_database_ok {
        return Err(DesktopLocalRuntimeError::Shutdown);
    }
    let database = database.await;""",
            )
        )

    def test_timeout_false_and_timeout_error_cannot_be_projected_as_success(self) -> None:
        for old, new in [
            ('"failed");\n            false', '"failed");\n            true'),
            ('"timed_out");\n            false', '"timed_out");\n            true'),
        ]:
            with self.subTest(owner_arm=old):
                self.assert_rejected(
                    replace_once(self.source, PROJECTION, PROJECTION.replace(old, new))
                )
        for old, new in [
            ("(succeeded, Some(original))", "(true, Some(original))"),
            ("(false, None)", "(true, None)"),
        ]:
            with self.subTest(helper_arm=old):
                self.assert_rejected(replace_after(self.source, HELPER, old, new))

    def test_shadowed_resource_alias_cannot_reuse_the_old_owner_binding(self) -> None:
        for declaration in [
            "let agent_host: Option<DesktopAgentHost> = None;",
            "let assembly: Option<PostgresApplicationAssembly> = None;",
        ]:
            with self.subTest(shadow=declaration):
                self.assert_rejected(
                    replace_once(
                        self.source,
                        "    let non_database = async {",
                        f"    {declaration}\n    let non_database = async {{",
                    )
                )
        with self.subTest(shadow="database owner"):
            source = replace_once(
                self.source,
                "    let database_result = match owner.data_plane.take() {",
                "    let database_owner = owner.data_plane.take();\n"
                "    let database_owner: Option<RunningDesktopLocalDataPlane> = None;\n"
                "    let database_result = match database_owner {",
            )
            self.assert_rejected(source)

    def test_shadowed_helper_parameter_is_not_a_database_stage(self) -> None:
        self.assert_rejected(
            replace_after(
                self.source,
                HELPER,
                HELPER_DATABASE,
                """    let database = async { Ok::<(), ()>(()) };
    let database = database.await;""",
            )
        )

    def test_database_shutdown_must_stay_in_the_independent_database_stage(self) -> None:
        self.assert_rejected(
            replace_once(
                self.source,
                "Some(data_plane) => data_plane.shutdown().await,",
                "Some(data_plane) => { drop(data_plane); Ok(()) },",
            )
        )
        self.assert_rejected(
            replace_once(
                self.source,
                "Some(data_plane) => data_plane.shutdown().await,",
                "Some(data_plane) => { let _ignored = data_plane.shutdown().await; Ok(()) },",
            )
        )
        self.assert_rejected(
            replace_once(
                self.source, DATABASE, DATABASE.replace("None => Err((", "None => Ok((")
            )
        )

    def test_armed_capture_gate_and_branch_shape_are_exact(self) -> None:
        # Only the cfg-gated armed flag may skip revocation; the ordinary build keeps false.
        self.assert_rejected(
            replace_once(self.source, CAPTURING_OFF, "    let capturing = true;\n")
        )
        self.assert_rejected(
            replace_once(
                self.source,
                AUTHORITY,
                "    let authority_ok = startup_ok || owner.lifecycle.shutdown_authority().is_ok();\n",
            )
        )
        # The job still carries the original owner, retained for the capture branch.
        self.assert_rejected(replace_once(self.source, "        owner: Some(owner),", "        owner: None,"))
        # The capture branch hands the job to one capture entry and ends the job itself.
        self.assert_rejected(replace_once(self.source, CAPTURE_ENTRY, CAPTURE_ENTRY + CAPTURE_ENTRY))
        self.assert_rejected(
            replace_once(self.source, CAPTURE_RETURN, "    }\n    let DesktopLocalClosingJob {")
        )
        self.assert_rejected(
            replace_once(
                self.source,
                "    if let Some(ready) = job.normal_ready.take() {",
                "    if let Some(ready) = job.normal_ready.clone() {",
            )
        )

    def test_database_owner_and_some_binding_aliases_are_accepted(self) -> None:
        source = replace_once(
            self.source,
            "    let database_result = match owner.data_plane.take() {",
            "    let database_owner = owner.data_plane.take();\n"
            "    let database_result = match database_owner {",
        )
        source = replace_once(
            source,
            "Some(data_plane) => data_plane.shutdown().await,",
            "Some(running_database) => running_database.shutdown().await,",
        )
        check_source(source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
