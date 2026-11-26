use std::env;

use agy_container::{allow, auth};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("allow") => {
            let groups: Vec<String> = args[1..].to_vec();
            match allow::compile_allow_fragment(&groups, &[]) {
                Ok(out) => print!("{out}"),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("broker") => match auth::render_api_broker_conf("AIzaCiTestPlaceholderKey0000") {
            Ok(out) => print!("{out}"),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        },
        _ => {
            eprintln!("usage: emit-squid-fragments <allow [groups...] | broker>");
            std::process::exit(2);
        }
    }
}
