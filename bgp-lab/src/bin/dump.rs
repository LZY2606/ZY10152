// Dump a built-in fixture's convergence trace as JSON (useful for offline inspection).
//   cargo run --bin dump -- dispute-wheel
use bgp_lab::engine::simulate;
use bgp_lab::fixtures::*;

fn main() {
    let which = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "dispute-wheel".into());
    let input = match which.as_str() {
        "basic" | "basic-preferences" => basic_preferences(),
        "med" | "med-community-rewrite" => med_community_rewrite(),
        "loop" | "as-path-loop" => as_path_loop(),
        "equal" | "equal-paths" => equal_paths(),
        "wheel" | "dispute-wheel" => dispute_wheel(),
        other => {
            eprintln!("unknown fixture {other}; use basic|med|loop|equal|wheel");
            std::process::exit(2);
        }
    };
    let result = simulate(&input);
    println!(
        "{}",
        serde_json::json!({ "input": input, "result": result })
    );
}
