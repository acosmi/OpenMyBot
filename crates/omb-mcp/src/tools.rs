//! The five tools and their fixed schemas; the daemon validates every argument once.
use rmcp::model::{JsonObject, Tool};
use std::sync::Arc;

/// One tool and the daemon operation it forwards to.
pub(crate) struct Def {
    pub(crate) name: &'static str,
    pub(crate) op: &'static str,
    description: &'static str,
    input: &'static str,
    output: &'static str,
}
pub(crate) const DEFS: [Def; 5] = [
    Def {
        name: "wrok_run_begin",
        op: "mcp_run_begin",
        description: "Start a background run in the workspace the owner bound to this host. Repeating the same operation_id with the same message returns the same run; the same operation_id with another message is refused.",
        input: r#"{"type":"object","properties":{"operation_id":{"type":"string","minLength":1,"maxLength":125,"pattern":"^[A-Za-z0-9._:-]+$"},"message":{"type":"string","maxLength":4096}},"required":["operation_id","message"],"additionalProperties":false}"#,
        output: r#"{"type":"object","properties":{"run_id":{"type":"string"},"thread_id":{"type":"string"},"state":{"type":"string","enum":["accepted","replayed"]}},"required":["run_id","thread_id","state"],"additionalProperties":false}"#,
    },
    Def {
        name: "wrok_run_status",
        op: "mcp_run_status",
        description: "Return the state of one run and the ids of the permission requests waiting for the owner.",
        input: r#"{"type":"object","properties":{"run_id":{"type":"string","minLength":1,"maxLength":128}},"required":["run_id"],"additionalProperties":false}"#,
        output: r#"{"type":"object","properties":{"run_id":{"type":"string"},"state":{"type":"string","enum":["pending","running","awaiting_permission","succeeded","failed","cancelled","reconciliation_required"]},"permission_ids":{"type":"array","items":{"type":"string"}}},"required":["run_id","state","permission_ids"],"additionalProperties":false}"#,
    },
    Def {
        name: "wrok_run_cancel",
        op: "mcp_run_cancel",
        description: "Request cancellation of one run. A run that has not started is cancelled at once.",
        input: r#"{"type":"object","properties":{"run_id":{"type":"string","minLength":1,"maxLength":128}},"required":["run_id"],"additionalProperties":false}"#,
        output: r#"{"type":"object","properties":{"run_id":{"type":"string"},"state":{"type":"string","enum":["requested","already_requested","already_terminal"]}},"required":["run_id","state"],"additionalProperties":false}"#,
    },
    Def {
        name: "wrok_run_result",
        op: "mcp_run_result",
        description: "Return the outcome, summary and artifact paths of a finished run.",
        input: r#"{"type":"object","properties":{"run_id":{"type":"string","minLength":1,"maxLength":128}},"required":["run_id"],"additionalProperties":false}"#,
        output: r#"{"type":"object","properties":{"run_id":{"type":"string"},"terminal_kind":{"type":"string","enum":["succeeded","failed","cancelled","reconciliation_required"]},"summary":{"type":["string","null"]},"artifacts":{"type":"array","items":{"type":"string"}}},"required":["run_id","terminal_kind","summary","artifacts"],"additionalProperties":false}"#,
    },
    Def {
        name: "wrok_thread_list",
        op: "mcp_thread_list",
        description: "List the most recent runs of this host, newest first, at most 50.",
        input: r#"{"type":"object","properties":{},"additionalProperties":false}"#,
        output: r#"{"type":"object","properties":{"runs":{"type":"array","maxItems":50,"items":{"type":"object","properties":{"run_id":{"type":"string"},"thread_id":{"type":"string"},"state":{"type":"string","enum":["pending","running","awaiting_permission","succeeded","failed","cancelled","reconciliation_required"]},"accepted_at":{"type":"string"}},"required":["run_id","thread_id","state","accepted_at"],"additionalProperties":false}}},"required":["runs"],"additionalProperties":false}"#,
    },
];
pub(crate) fn list() -> Vec<Tool> {
    DEFS.iter()
        .map(|def| {
            Tool::new(def.name, def.description, schema(def.input))
                .with_raw_output_schema(schema(def.output))
        })
        .collect()
}
fn schema(text: &str) -> Arc<JsonObject> {
    Arc::new(serde_json::from_str(text).expect("fixed schema text"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn parsed(text: &str) -> Value {
        let value: Value = serde_json::from_str(text).unwrap();
        assert!(value.is_object(), "{text}");
        value
    }
    const STATES: [&str; 7] = [
        "pending",
        "running",
        "awaiting_permission",
        "succeeded",
        "failed",
        "cancelled",
        "reconciliation_required",
    ];

    #[test]
    fn tool_names_ops_and_order_are_the_spec_five() {
        let names: Vec<&str> = DEFS.iter().map(|def| def.name).collect();
        assert_eq!(
            names,
            [
                "wrok_run_begin",
                "wrok_run_status",
                "wrok_run_cancel",
                "wrok_run_result",
                "wrok_thread_list",
            ]
        );
        let ops: Vec<&str> = DEFS.iter().map(|def| def.op).collect();
        assert_eq!(
            ops,
            [
                "mcp_run_begin",
                "mcp_run_status",
                "mcp_run_cancel",
                "mcp_run_result",
                "mcp_thread_list",
            ]
        );
        for def in &DEFS {
            assert_eq!(
                def.op,
                format!("mcp_{}", def.name.strip_prefix("wrok_").unwrap())
            );
        }
        let tools = list();
        assert_eq!(tools.len(), 5);
        for (tool, def) in tools.iter().zip(&DEFS) {
            assert_eq!(tool.name, def.name);
            assert_eq!(tool.description.as_deref(), Some(def.description));
        }
    }

    #[test]
    fn input_schemas_are_closed_and_exact() {
        let run = json!({
            "type": "object",
            "properties": {"run_id": {"type": "string", "minLength": 1, "maxLength": 128}},
            "required": ["run_id"],
            "additionalProperties": false
        });
        let expected = [
            json!({
                "type": "object",
                "properties": {
                    "operation_id": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 125,
                        "pattern": "^[A-Za-z0-9._:-]+$"
                    },
                    "message": {"type": "string", "maxLength": 4096}
                },
                "required": ["operation_id", "message"],
                "additionalProperties": false
            }),
            run.clone(),
            run.clone(),
            run,
            json!({"type": "object", "properties": {}, "additionalProperties": false}),
        ];
        for (def, expected) in DEFS.iter().zip(expected) {
            let input = parsed(def.input);
            assert_eq!(input, expected, "{}", def.name);
            assert_eq!(input["additionalProperties"], false);
        }
        let begin = parsed(DEFS[0].input);
        assert_eq!(begin["properties"]["operation_id"]["maxLength"], 125);
        assert_eq!(begin["properties"]["message"]["maxLength"], 4096);
        for def in &DEFS[1..4] {
            let run_id = &parsed(def.input)["properties"]["run_id"];
            assert_eq!(run_id["minLength"], 1);
            assert_eq!(run_id["maxLength"], 128);
        }
        assert_eq!(parsed(DEFS[4].input)["properties"], json!({}));
    }

    #[test]
    fn output_schemas_are_closed_and_exact() {
        let expected = [
            json!({
                "type": "object",
                "properties": {
                    "run_id": {"type": "string"},
                    "thread_id": {"type": "string"},
                    "state": {"type": "string", "enum": ["accepted", "replayed"]}
                },
                "required": ["run_id", "thread_id", "state"],
                "additionalProperties": false
            }),
            json!({
                "type": "object",
                "properties": {
                    "run_id": {"type": "string"},
                    "state": {"type": "string", "enum": STATES},
                    "permission_ids": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["run_id", "state", "permission_ids"],
                "additionalProperties": false
            }),
            json!({
                "type": "object",
                "properties": {
                    "run_id": {"type": "string"},
                    "state": {
                        "type": "string",
                        "enum": ["requested", "already_requested", "already_terminal"]
                    }
                },
                "required": ["run_id", "state"],
                "additionalProperties": false
            }),
            json!({
                "type": "object",
                "properties": {
                    "run_id": {"type": "string"},
                    "terminal_kind": {"type": "string", "enum": STATES[3..]},
                    "summary": {"type": ["string", "null"]},
                    "artifacts": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["run_id", "terminal_kind", "summary", "artifacts"],
                "additionalProperties": false
            }),
            json!({
                "type": "object",
                "properties": {
                    "runs": {
                        "type": "array",
                        "maxItems": 50,
                        "items": {
                            "type": "object",
                            "properties": {
                                "run_id": {"type": "string"},
                                "thread_id": {"type": "string"},
                                "state": {"type": "string", "enum": STATES},
                                "accepted_at": {"type": "string"}
                            },
                            "required": ["run_id", "thread_id", "state", "accepted_at"],
                            "additionalProperties": false
                        }
                    }
                },
                "required": ["runs"],
                "additionalProperties": false
            }),
        ];
        for (def, expected) in DEFS.iter().zip(expected) {
            let output = parsed(def.output);
            assert_eq!(output, expected, "{}", def.name);
            assert_eq!(output["additionalProperties"], false);
        }
        assert_eq!(
            parsed(DEFS[1].output)["properties"]["state"]["enum"],
            json!(STATES)
        );
        assert_eq!(
            parsed(DEFS[3].output)["properties"]["terminal_kind"]["enum"],
            json!([
                "succeeded",
                "failed",
                "cancelled",
                "reconciliation_required"
            ])
        );
        assert_eq!(
            parsed(DEFS[2].output)["properties"]["state"]["enum"],
            json!(["requested", "already_requested", "already_terminal"])
        );
        let runs = &parsed(DEFS[4].output)["properties"]["runs"];
        assert_eq!(runs["maxItems"], 50);
        assert_eq!(runs["items"]["properties"]["state"]["enum"], json!(STATES));
    }
}
