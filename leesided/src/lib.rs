//! leesided: the Leeside engine. See docs/rules.md for the rules module and
//! ../docs/brief.md for the event schema and the check protocol.

pub mod actors;
pub mod api;
pub mod check;
pub mod config;
pub mod engine;
pub mod enrich;
pub mod export;
pub mod hash;
pub mod ingest;
pub mod labels;
pub mod llm;
pub mod report;
pub mod review;
pub mod rules;
pub mod store;
pub mod tap;
pub mod windside;
