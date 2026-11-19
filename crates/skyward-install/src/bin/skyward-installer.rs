use anyhow::{ensure, Context, Result};
use skyward_install::upgrade;
use skyward_vab::Slot;
use std::io::Write;
use std::path::Path;

fn install() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    #[cfg(not(target_os = "android"))]
    if args.get(1).is_some_and(|arg| arg == "--test-install") {
        ensure!(args.len() == 6, "usage: skyward-installer --test-install ZIP BY_NAME CODENAME SLOT");
        let recovery = upgrade::unzip(Path::new(&args[2]))?;
        upgrade::check(&recovery, &args[4])?;
        let slot = match args[5].as_str() {
            "a" => Slot::A,
            "b" => Slot::B,
            _ => anyhow::bail!("slot must be a or b"),
        };
        return upgrade::write_vendor_boot(Path::new(&args[3]), &recovery, &[slot], &mut |_, _| {});
    }
    ensure!(args.len() >= 4, "expected recovery API version, output descriptor and package path");
    let fd: u32 = args[2].parse().context("invalid recovery output descriptor")?;
    let mut output = std::fs::OpenOptions::new().write(true).open(format!("/proc/self/fd/{fd}"))?;
    let recovery = upgrade::unzip(Path::new(&args[3]))?;
    let codename = skyward_sys::prop("ro.product.device").context("ro.product.device is unset")?;
    upgrade::check(&recovery, &codename)?;
    let slot = match skyward_sys::prop("ro.boot.slot_suffix").as_deref() {
        Some("_a") => Slot::A,
        Some("_b") => Slot::B,
        _ => anyhow::bail!("invalid current slot suffix"),
    };
    writeln!(output, "ui_print Installing Skyward to the current slot\nui_print")?;
    upgrade::write_vendor_boot(Path::new(skyward_block::BY_NAME), &recovery, &[slot], &mut |done, total| {
        let _ = writeln!(output, "set_progress {}", done as f64 / total as f64);
    })?;
    writeln!(output, "ui_print Skyward installed\nui_print")?;
    Ok(())
}

fn main() {
    if let Err(error) = install() {
        eprintln!("Skyward installation failed: {error:#}");
        std::process::exit(1);
    }
}
