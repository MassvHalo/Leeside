//! JSON Schema export of the rule document, derived from the same structs
//! the engine deserialises. This is what goes into Spark's prompt and what
//! `GET /rules/schema` serves; nobody hand-writes a second copy.

use super::model::Rule;
use schemars::schema::RootSchema;

pub fn rule_schema() -> RootSchema {
    schemars::schema_for!(Rule)
}

pub fn rule_schema_json() -> String {
    serde_json::to_string_pretty(&rule_schema()).expect("schema serialises")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_names_every_top_level_field_and_forbids_extras() {
        let v: serde_json::Value = serde_json::from_str(&rule_schema_json()).unwrap();
        let props = v["properties"].as_object().unwrap();
        for key in [
            "id",
            "note",
            "mode",
            "action",
            "retry_after_s",
            "match",
            "when",
            "expires_at",
            "origin",
        ] {
            assert!(props.contains_key(key), "missing {key}");
        }
        assert_eq!(v["additionalProperties"], serde_json::json!(false));
        let required: Vec<&str> = v["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap())
            .collect();
        assert_eq!(
            required,
            ["action", "id", "match", "mode", "note", "origin"]
        );
    }

    #[test]
    fn schema_lists_the_action_and_mode_ladders() {
        let v: serde_json::Value = serde_json::from_str(&rule_schema_json()).unwrap();
        let defs = &v["definitions"];
        assert_eq!(
            defs["Mode"]["enum"],
            serde_json::json!(["monitor", "shadow", "enforce"])
        );
        assert_eq!(
            defs["Action"]["enum"],
            serde_json::json!(["log", "watch", "rate_limit", "challenge", "block"])
        );
    }
}
