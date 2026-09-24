// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Ok(secret) = std::env::var("SSP_ASKPASS_SECRET") {
        let secret = zeroize::Zeroizing::new(secret);
        let prompt = std::env::args().nth(1).unwrap_or_default().to_lowercase();
        // Never answer host-trust or other non-credential prompts with a secret.
        if prompt.contains("password") || prompt.contains("passphrase") {
            use std::io::Write;
            let mut output = std::io::stdout().lock();
            if writeln!(output, "{}", secret.as_str()).is_ok() {
                return;
            }
        }
        std::process::exit(1);
    }
    secureshell_pro_lib::run()
}
