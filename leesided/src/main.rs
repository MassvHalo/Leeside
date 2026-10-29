fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next().as_deref()) {
        (Some("rules"), Some("schema")) => {
            println!("{}", leesided::rules::schema::rule_schema_json())
        }
        (Some("rules"), Some("validate")) => {
            let path = args.next().expect("usage: leesided rules validate <file>");
            let text = std::fs::read_to_string(&path).expect("read rule file");
            match leesided::rules::model::Rule::parse(&text, now_s()) {
                Ok(_) => println!("ok"),
                Err(errors) => {
                    for e in &errors {
                        println!("{}: {}", e.path, e.message);
                    }
                    std::process::exit(1);
                }
            }
        }
        _ => tracing::info!("leesided scaffold; serve arrives in session B"),
    }
}

fn now_s() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
