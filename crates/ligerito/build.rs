// Build script for ligerito
// Prints warnings about performance optimizations during build

fn main() {
    // Check if SIMD instructions are enabled
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let has_pclmulqdq = std::env::var("CARGO_CFG_TARGET_FEATURE")
        .map(|features| features.split(',').any(|f| f == "pclmulqdq"))
        .unwrap_or(false);

    // Check if we're in release mode
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let is_release = profile == "release";

    // Warn if building without SIMD on x86_64
    if target_arch == "x86_64" && !has_pclmulqdq && is_release {
        println!("cargo:warning=");
        println!(
            "cargo:warning=╔═══════════════════════════════════════════════════════════════════╗"
        );
        println!(
            "cargo:warning=║  PERFORMANCE WARNING: SIMD instructions not enabled!             ║"
        );
        println!(
            "cargo:warning=║                                                                   ║"
        );
        println!(
            "cargo:warning=║  This build will be 5-6x slower than optimized builds.           ║"
        );
        println!(
            "cargo:warning=║                                                                   ║"
        );
        println!(
            "cargo:warning=║  For optimal performance, rebuild with:                          ║"
        );
        println!(
            "cargo:warning=║    RUSTFLAGS=\"-C target-cpu=native\" cargo install ligerito      ║"
        );
        println!(
            "cargo:warning=║                                                                   ║"
        );
        println!(
            "cargo:warning=║  Or install from source:                                         ║"
        );
        println!(
            "cargo:warning=║    git clone https://github.com/rotkonetworks/zeratul            ║"
        );
        println!(
            "cargo:warning=║    cd zeratul                                                     ║"
        );
        println!(
            "cargo:warning=║    cargo install --path crates/ligerito                          ║"
        );
        println!(
            "cargo:warning=╚═══════════════════════════════════════════════════════════════════╝"
        );
        println!("cargo:warning=");
    }

    // Also warn if not release build
    if !is_release {
        println!("cargo:warning=DEBUG BUILD: Performance will be very slow. Use --release flag.");
    }
}
