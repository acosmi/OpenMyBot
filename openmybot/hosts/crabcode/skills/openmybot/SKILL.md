---
name: openmybot
description: Start, inspect, cancel and fetch the result of background runs through the local OpenMyBot daemon.
---

# OpenMyBot background runs

These tools hand work to the local OpenMyBot daemon and report on it. Each run executes in the workspace the owner bound to this host, under the owner's permission rules. Nothing here can approve or deny a permission request.

## Tools

- `wrok_run_begin` with `operation_id` and `message` starts a run. `operation_id` is 1 to 125 characters from `A-Za-z0-9._:-`; use a new one for each intended run. Repeating the same `operation_id` with the same `message` returns the same run (`state` is `replayed`); the same `operation_id` with another `message` fails with `operation_conflict`. `message` is at most 4096 bytes of UTF-8 text. The result holds `run_id`, `thread_id` and `state` (`accepted` or `replayed`).
- `wrok_run_status` with `run_id` returns `run_id`, `state` and `permission_ids`. `state` is one of `pending`, `running`, `awaiting_permission`, `succeeded`, `failed`, `cancelled` and `reconciliation_required`. `permission_ids` lists the permission requests waiting for the owner, who answers them with `openmybot approve <permission_id>` or `openmybot deny <permission_id>`.
- `wrok_run_cancel` with `run_id` asks for cancellation and returns `run_id` and `state`: `requested`, `already_requested` or `already_terminal`. A run that has not started is cancelled at once.
- `wrok_run_result` with `run_id` returns `run_id`, `terminal_kind`, `summary` (text or null) and `artifacts` (relative paths) once the run has finished; before that it fails with `run_not_terminal`. A summary is kept for seven days.
- `wrok_thread_list` takes no arguments and returns `runs`: at most 50 entries, newest first, each with `run_id`, `thread_id`, `state` and `accepted_at`.

## Failures

A failed call returns an error result whose text is one code:

- `wrok_not_running`: the daemon is not running. Ask the owner to start `openmybot daemon`; these tools never start it.
- `host_not_bound`: no host binding exists. Ask the owner to run `openmybot bindings host crabcode --workspace <directory>`.
- `host_binding_suspended`: the owner has to run `openmybot bindings reconfirm <binding_id>`.
- `run_not_found`: the run does not belong to this host binding.
- `dispatch_queue_full`: 20 runs are already waiting; try again later.
- `operation_conflict` and `run_not_terminal`: described with the tools above.
- `invalid_request`: an argument is missing, unknown or outside its limits.
- `nested_delegation_refused`: this process was started by OpenMyBot itself and cannot start further runs.
- `request_timeout`, `binding_failed`, `internal_error`: the daemon did not answer in time or failed; the owner can check `openmybot status`.

## Setup

The `openmybot` command must be on the `PATH` of the host. The daemon, the host and this server must use the same data directory; set `OPENMYBOT_DATA_DIR` in the host's environment when it is not the default one.
