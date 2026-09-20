use bgp_lab::api::App;

fn main() {
    let mut listen = "127.0.0.1:5352".to_string();
    let mut db = "bgp-lab.sqlite".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                listen = args.next().expect("--listen requires an address");
            }
            "--db" => {
                db = args.next().expect("--db requires a path");
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let app = App::new(&db).expect("open store");
    app.seed_fixtures().expect("seed fixtures");
    (&app).serve(&listen).expect("server error");
}
