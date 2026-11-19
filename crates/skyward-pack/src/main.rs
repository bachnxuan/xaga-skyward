use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use skyward_config::ramdisk as paths;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

mod described;
mod policy;

use skyward_bootimg::{BootImage, Ramdisk, VendorBootImage, avb};

/// Builds Skyward recovery images from a device's own stock images.
#[derive(Parser)]
#[command(name = "skyward-pack")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print an image's header and the files in its ramdisk.
    List { image: PathBuf },
    /// Write one ramdisk file to stdout.
    Cat { image: PathBuf, path: String },
    /// Unpack and pack an image's ramdisk unchanged, to check that a rebuilt
    /// archive keeps every entry.
    Repack { image: PathBuf, out: PathBuf },
    /// Build a standalone Skyward recovery fragment from an AOSP template.
    Payload {
        #[arg(long)]
        template: PathBuf,
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        system_init: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        font: PathBuf,
        #[arg(long)]
        mono: PathBuf,
        #[arg(long)]
        mono_license: PathBuf,
        #[arg(long = "add", value_name = "NAME=PATH")]
        add: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Prepare an unsigned vendor_boot from a target-local base.
    PrepareVendorBoot {
        #[arg(long)]
        base: PathBuf,
        #[arg(long)]
        recovery: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        check_only: bool,
    },
    /// Create a recovery-installable ZIP from a payload and Android installer.
    Installer {
        #[arg(long)]
        recovery: PathBuf,
        #[arg(long)]
        installer: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Join a kernel and another image's ramdisk into one boot image.
    Boot {
        /// Image holding the kernel (the device's boot partition).
        #[arg(long)]
        kernel: PathBuf,
        /// Image holding the ramdisk.
        #[arg(long)]
        ramdisk: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Build a Skyward recovery image on top of the device's stock recovery:
    /// its init, adbd, SELinux policy and libraries stay, the recovery
    /// service becomes Skyward. The image fills the whole partition and ends
    /// in an unsigned AVB footer of its own. This command is for a
    /// dedicated recovery boot image.
    Recovery {
        /// The device's stock recovery image: the whole partition, as the
        /// phone or a full update package holds it, ending in its AVB
        /// footer.
        #[arg(long)]
        stock: PathBuf,
        /// Skyward built for the device (aarch64-linux-android).
        #[arg(long)]
        binary: PathBuf,
        /// The first program of a system installed beside the installed
        /// one, skyward-system-init built for the device and linked
        /// statically.
        #[arg(long)]
        system_init: PathBuf,
        /// The device configuration, devices/<codename>.toml.
        #[arg(long)]
        config: PathBuf,
        /// The UI typeface.
        #[arg(long)]
        font: PathBuf,
        /// The terminal's monospaced typeface.
        #[arg(long)]
        mono: PathBuf,
        /// The monospaced typeface's licence, which goes with it.
        #[arg(long)]
        mono_license: PathBuf,
        /// A file to put in the ramdisk, as NAME=PATH: the name it has in
        /// the archive, and the file on this computer.
        #[arg(long = "add", value_name = "NAME=PATH")]
        add: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the stock build a device's recovery is made on, as lines of
    /// name=value: its version, where its full update package is, and the
    /// SHA-256 of the recovery partition in that package. Given somewhere
    /// to write it, also take that partition out of the package on its
    /// server, reading only what the partition takes, and write it there
    /// once its SHA-256 is that one.
    Stock {
        /// The device configuration, devices/<codename>.toml.
        #[arg(long)]
        config: PathBuf,
        /// Where to write the stock recovery image.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Take what a device's own partitions say of the programs they carry
    /// out of its stock build's full update package on its server: the
    /// init scripts, the service descriptions, the accounts and the build
    /// properties of each partition that carries such programs, written
    /// under `out` as the partition and then the path in it. Only the
    /// parts of the package that hold these files are downloaded, each
    /// checked against the package's own sum of it.
    Described {
        /// The device configuration, devices/<codename>.toml.
        #[arg(long)]
        config: PathBuf,
        /// A partition to take them out of; vendor, odm and system_ext
        /// when none is named.
        #[arg(long = "partition")]
        partitions: Vec<String>,
        /// The folder to write the files under, which is not there yet.
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Payload {
            template,
            binary,
            system_init,
            config,
            font,
            mono,
            mono_license,
            add,
            out,
        } => {
            let device = skyward_config::DeviceConfig::load(&config)?;
            let data = bounded(&template)?;
            let fragment = if data.starts_with(b"VNDRBOOT") {
                let image = VendorBootImage::parse(&data)?;
                match image.recovery() {
                    Ok(Some(recovery)) => recovery.to_vec(),
                    _ if image.header.v4.is_none() || image.table.len() == 1 => image.ramdisk,
                    _ => anyhow::bail!("template has no unambiguous AOSP recovery ramdisk"),
                }
            } else if data.starts_with(b"ANDROID!") {
                BootImage::parse(&data)?.ramdisk
            } else {
                data
            };
            let mut rd = Ramdisk::decode(&fragment)?;
            let files = Packed {
                binary: &binary,
                system_init: &system_init,
                config: &config,
                font: &font,
                mono: &mono,
                mono_license: &mono_license,
            };
            edit_ramdisk(
                &mut rd,
                &template,
                &files,
                &add,
                true,
                &device.device.codename,
            )?;
            rd.entries.retain(|entry| {
                let name = entry.name.trim_start_matches("./").trim_start_matches('/');
                !["lib/modules", "system/lib/modules", "vendor/lib/modules"]
                    .iter()
                    .any(|path| name == *path || name.starts_with(&format!("{path}/")))
            });
            publish(
                &out,
                &[
                    &template,
                    &binary,
                    &system_init,
                    &config,
                    &font,
                    &mono,
                    &mono_license,
                ],
                &rd.encode()?,
            )?;
            Ok(())
        }
        Cmd::PrepareVendorBoot {
            base,
            recovery,
            out,
            check_only,
        } => {
            check_output(&out, &[&base, &recovery])?;
            let source = bounded(&base)?;
            let payload = bounded(&recovery)?;
            let (output, stripped) = VendorBootImage::prepare(&source, &payload)?;
            let before = VendorBootImage::parse(&source)?;
            let after = VendorBootImage::parse(&output)?;
            let report_image = |image: &VendorBootImage| {
                let fragments: Vec<_> = image.table.iter().map(|entry| {
                    let start = entry.offset as usize;
                    let end = start + entry.size as usize;
                    serde_json::json!({
                        "name": String::from_utf8_lossy(&entry.name[..entry.name.iter().position(|&b| b == 0).unwrap_or(32)]),
                        "type": entry.kind, "offset": entry.offset, "size": entry.size,
                        "board_ids": entry.board_id,
                        "sha256": hex::encode(Sha256::digest(&image.ramdisk[start..end]))
                    })
                }).collect();
                serde_json::json!({
                    "page_size": image.header.page_size,
                    "kernel_addr": image.header.kernel_addr,
                    "ramdisk_addr": image.header.ramdisk_addr,
                    "tags_addr": image.header.tags_addr,
                    "dtb_addr": image.header.dtb_addr,
                    "board": hex::encode(image.header.board_name),
                    "cmdline_sha256": hex::encode(Sha256::digest(image.header.cmdline.as_ref())),
                    "dtb_sha256": hex::encode(Sha256::digest(&image.dtb)),
                    "bootconfig_sha256": hex::encode(Sha256::digest(&image.bootconfig)),
                    "fragments": fragments
                })
            };
            println!(
                "{}",
                serde_json::json!({
                    "base_sha256": hex::encode(Sha256::digest(&source)),
                    "recovery_sha256": hex::encode(Sha256::digest(&payload)),
                    "output_sha256": hex::encode(Sha256::digest(&output)),
                    "action": if before.recovery()?.is_some() { "replace" } else { "append" },
                    "base": report_image(&before), "output": report_image(&after),
                    "output_size": output.len(), "check_only": check_only,
                    "avb_footer_stripped": stripped, "output_unsigned": true
                })
            );
            if !check_only {
                publish(&out, &[&base, &recovery], &output)?;
            }
            Ok(())
        }
        Cmd::Installer {
            recovery,
            installer,
            out,
        } => {
            let payload = bounded(&recovery)?;
            let binary = bounded(&installer)?;
            let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            archive.start_file(
                "META-INF/com/google/android/update-binary",
                options.unix_permissions(0o755),
            )?;
            archive.write_all(&binary)?;
            archive.start_file("skyward/recovery.cpio", options)?;
            archive.write_all(&payload)?;
            let bytes = archive.finish()?.into_inner();
            publish(&out, &[&recovery, &installer], &bytes)
        }
        Cmd::List { image } => list(&image),
        Cmd::Cat { image, path } => {
            let rd = Ramdisk::decode(Image::read(&image)?.ramdisk())?;
            let e = rd
                .find(&path)
                .with_context(|| format!("{path} is not in the ramdisk"))?;
            std::io::stdout().write_all(&e.data)?;
            Ok(())
        }
        Cmd::Repack { image, out } => {
            let mut img = Image::read(&image)?;
            let ramdisk = Ramdisk::decode(img.ramdisk())?.encode()?;
            img.set_ramdisk(ramdisk)?;
            let bytes = img.to_bytes()?;
            std::fs::write(&out, &bytes).with_context(|| format!("write {}", out.display()))?;
            println!("wrote {} ({} bytes)", out.display(), bytes.len());
            Ok(())
        }
        Cmd::Boot {
            kernel,
            ramdisk,
            out,
        } => {
            let mut img = BootImage::read(&ramdisk)?;
            img.kernel = BootImage::read(&kernel)?.kernel;
            write(&out, &img, &img.to_bytes()?)
        }
        Cmd::Recovery {
            stock,
            binary,
            system_init,
            config,
            font,
            mono,
            mono_license,
            add,
            out,
        } => {
            let size = partition_size(&stock)?;
            let device = skyward_config::DeviceConfig::load(&config)?;
            let mut img = Image::read(&stock)?;
            ensure!(
                !matches!(img, Image::Vendor(_)),
                "vendor_boot requires the payload and installer commands"
            );
            let mut rd = Ramdisk::decode(img.ramdisk())?;
            let files = Packed {
                binary: &binary,
                system_init: &system_init,
                config: &config,
                font: &font,
                mono: &mono,
                mono_license: &mono_license,
            };
            edit_ramdisk(&mut rd, &stock, &files, &add, true, &device.device.codename)?;
            img.set_ramdisk(rd.encode()?)?;
            let bytes = img.to_bytes()?;
            let partition = match img {
                Image::Boot(_) => "recovery",
                Image::Vendor(_) => "vendor_boot",
            };
            let footed = avb::footed(&bytes, partition, size, &Sha256::digest(&bytes))?;
            std::fs::write(&out, &footed).with_context(|| format!("write {}", out.display()))?;
            println!(
                "wrote {} ({} bytes of image, {} bytes in all, ending in an unsigned {partition} footer)",
                out.display(),
                bytes.len(),
                footed.len()
            );
            Ok(())
        }
        Cmd::Stock { config, out } => {
            let cfg = skyward_config::DeviceConfig::load(&config)?;
            let stock = cfg
                .stock
                .as_ref()
                .with_context(|| format!("{} names no stock build", config.display()))?;
            println!("version={}\nrecovery={}", stock.version, stock.recovery);
            if let Some(package) = &stock.package {
                println!("package={package}");
            } else if let Some(image) = &stock.image {
                println!("image={image}");
            }
            match out {
                Some(out) => take_stock_recovery(stock, &cfg.device.recovery_partition, &out),
                None => Ok(()),
            }
        }
        Cmd::Described {
            config,
            partitions,
            out,
        } => {
            let stock = skyward_config::DeviceConfig::load(&config)?
                .stock
                .with_context(|| format!("{} names no stock build", config.display()))?;
            let partitions = if partitions.is_empty() {
                skyward_programs::phone::PARTITIONS
                    .map(str::to_string)
                    .to_vec()
            } else {
                partitions
            };
            let package = stock
                .package
                .as_deref()
                .context("described requires a full OTA package, not a standalone image")?;
            described::take(package, &partitions, &out)
        }
    }
}

fn bounded(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() > 0 && meta.len() <= 64 * 1024 * 1024,
        "{} is not a bounded regular file",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= 64 * 1024 * 1024,
        "{} exceeds 64 MiB or is empty",
        path.display()
    );
    Ok(bytes)
}

fn check_output(out: &Path, inputs: &[&Path]) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let resolved = parent
        .canonicalize()?
        .join(out.file_name().context("output has no filename")?);
    let output = match std::fs::symlink_metadata(out) {
        Ok(meta) => {
            ensure!(
                meta.is_file() && !meta.file_type().is_symlink(),
                "output must be a regular file, not a link"
            );
            Some(meta)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    for input in inputs {
        let meta = std::fs::metadata(input)?;
        ensure!(
            input.canonicalize()? != resolved
                && !output
                    .as_ref()
                    .is_some_and(|o| o.dev() == meta.dev() && o.ino() == meta.ino()),
            "output aliases {}",
            input.display()
        );
    }
    Ok(())
}

fn publish(out: &Path, inputs: &[&Path], bytes: &[u8]) -> Result<()> {
    check_output(out, inputs)?;
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    check_output(out, inputs)?;
    staged
        .persist(out)
        .map_err(|e| e.error)
        .with_context(|| format!("publish {}", out.display()))?;
    Ok(())
}

/// Take the partition the recovery is made on out of the stock build's full
/// update package on its server, reading only what that partition takes of
/// it, and write it to `out` once its SHA-256 is the one the configuration
/// names. A phone whose recovery lives in its vendor boot image names that
/// partition rather than a recovery one.
fn take_stock_recovery(stock: &skyward_config::Stock, partition: &str, out: &Path) -> Result<()> {
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).with_context(|| format!("make {}", parent.display()))?;
    if let Some(url) = &stock.image {
        let mut response = ureq::get(url)
            .call()
            .with_context(|| format!("download {url}"))?;
        return take_direct(response.body_mut().as_reader(), &stock.recovery, out);
    }
    let package = stock
        .package
        .as_deref()
        .context("stock has no OTA package")?;
    // Taken out beside where it goes, so it is moved there whole.
    let work = tempfile::Builder::new()
        .prefix(".stock")
        .tempdir_in(parent)
        .with_context(|| format!("make a folder in {}", parent.display()))?;
    let payload =
        unpayload::Payload::open_url(package).with_context(|| format!("open {package}"))?;
    let options = unpayload::ExtractOptions {
        output_dir: work.path().to_path_buf(),
        partitions: vec![partition.into()],
        ..Default::default()
    };
    let report = |event: unpayload::Event<'_>| match event {
        unpayload::Event::Started { partitions } => {
            for (name, bytes) in partitions {
                println!("taking {name} out of the package: {bytes} bytes");
            }
        }
        unpayload::Event::Extracted(image) => {
            println!("took {} out: {} bytes", image.partition, image.size)
        }
        unpayload::Event::Progress { .. } => {}
    };
    let taken = payload
        .extract(&options, &report)
        .with_context(|| format!("take {partition} out of {package}"))?;
    let image = taken
        .iter()
        .find(|i| i.partition == partition)
        .with_context(|| format!("{package} holds no {partition} partition"))?;
    let sum = hex::encode(
        image
            .sha256
            .as_deref()
            .context("the package's own sum of the image was not checked")?,
    );
    ensure!(
        sum == stock.recovery,
        "the {partition} partition in {package} has the SHA-256 {sum}, where the configuration names {}",
        stock.recovery
    );
    std::fs::rename(&image.path, out)
        .with_context(|| format!("move {} to {}", image.path.display(), out.display()))?;
    println!(
        "wrote {} ({} bytes), its SHA-256 the one the configuration names",
        out.display(),
        image.size
    );
    Ok(())
}

fn take_direct(reader: impl Read, expected: &str, out: &Path) -> Result<()> {
    let mut bytes = Vec::new();
    reader.take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= 64 * 1024 * 1024,
        "image is empty or exceeds 64 MiB"
    );
    let sum = hex::encode(Sha256::digest(&bytes));
    ensure!(
        sum == expected,
        "image SHA-256 is {sum}, expected {expected}"
    );
    Image::parse(&bytes).context("parse downloaded image")?;
    publish(out, &[], &bytes)
}

/// The size of the partition `stock` fills: all of it, as the phone and a
/// full update package hold it, which its AVB footer ends.
fn partition_size(stock: &Path) -> Result<usize> {
    let mut file = File::open(stock).with_context(|| format!("open {}", stock.display()))?;
    let size = file
        .metadata()
        .with_context(|| format!("stat {}", stock.display()))?
        .len();
    let mut magic = [0u8; 4];
    if size >= 64 {
        file.seek(SeekFrom::Start(size - 64))
            .with_context(|| format!("seek in {}", stock.display()))?;
        file.read_exact(&mut magic)
            .with_context(|| format!("read {}", stock.display()))?;
    }
    ensure!(
        &magic == b"AVBf",
        "{} does not end in an AVB footer; give the whole recovery partition, as the phone or a full update package holds it",
        stock.display()
    );
    Ok(usize::try_from(size)?)
}

/// What a recovery image says about the build it is: the version and patch
/// levels of its own ramdisk's system and vendor partition, which are older
/// than those installed beside it whenever the phone has taken an update.
/// The phone's secure services read these to tell the secure world which
/// build is running, and keys the installed system made are refused when
/// they say the wrong one, so they are left out here for the recovery to
/// fill in from the installed system once it has that mounted.
const BUILD_VERSION: [&str; 3] = [
    "ro.build.version.release",
    "ro.build.version.security_patch",
    "ro.vendor.build.security_patch",
];

/// The scheduling profiles a recovery's programs look up by name. A
/// recovery's cgroup setup mounts no controllers, so of all a system's
/// profiles do, only the timer slack applies here.
const TASK_PROFILES: &[u8] = include_bytes!("task_profiles.json");

/// The init rules that give the USB port file transfer beside adb, which a
/// stock recovery does not offer.
const MTP_RC: &[u8] = include_bytes!("mtp.rc");

/// A property file without the lines that set any of `names`.
fn without(props: &[u8], names: &[&str]) -> Vec<u8> {
    let mut out = Vec::with_capacity(props.len());
    for line in props.split_inclusive(|b| *b == b'\n') {
        let key = line.split(|b| *b == b'=').next().unwrap_or_default();
        if !names.iter().any(|n| n.as_bytes() == key) {
            out.extend_from_slice(line);
        }
    }
    out
}

/// Write `bytes`, the image `img` makes, to `out`.
/// An image the packer reads: a boot image for a `recovery`, `boot` or
/// `init_boot` partition, or a vendor boot image for a `vendor_boot` one,
/// as MediaTek phones whose recovery rides there use.
enum Image {
    Boot(BootImage),
    Vendor(VendorBootImage),
}

impl Image {
    fn read(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        Image::parse(&bytes).with_context(|| format!("read {}", path.display()))
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.starts_with(b"VNDRBOOT") {
            Ok(Image::Vendor(VendorBootImage::parse(bytes)?))
        } else {
            Ok(Image::Boot(BootImage::parse(bytes)?))
        }
    }

    fn ramdisk(&self) -> &[u8] {
        match self {
            Image::Boot(img) => &img.ramdisk,
            Image::Vendor(img) => &img.ramdisk,
        }
    }

    fn set_ramdisk(&mut self, ramdisk: Vec<u8>) -> Result<()> {
        match self {
            Image::Boot(img) => img.ramdisk = ramdisk,
            Image::Vendor(img) => *img = img.with_ramdisk(ramdisk)?,
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Image::Boot(img) => img.to_bytes(),
            Image::Vendor(img) => img.to_bytes(),
        }
    }
}

/// The files Skyward is packed from.
struct Packed<'a> {
    binary: &'a Path,
    system_init: &'a Path,
    config: &'a Path,
    font: &'a Path,
    mono: &'a Path,
    mono_license: &'a Path,
}

/// What Skyward adds to a stock ramdisk and changes in it.
fn edit_ramdisk(
    rd: &mut Ramdisk,
    stock: &Path,
    files: &Packed<'_>,
    add: &[String],
    legacy_properties: bool,
    device: &str,
) -> Result<()> {
    // A stock recovery ramdisk has no third-party tree; refuse to build on
    // top of another custom recovery.
    if let Some(e) = rd
        .entries
        .iter()
        .find(|e| e.name == "FFiles" || e.name.starts_with("twres"))
    {
        anyhow::bail!(
            "{} holds {}, which is not a stock recovery",
            stock.display(),
            e.name
        );
    }
    let read = |p: &Path| std::fs::read(p).with_context(|| format!("read {}", p.display()));
    rd.replace(paths::RECOVERY, read(files.binary)?)?;
    // Install scripts look for the commands a stock recovery lacks among
    // its programs, and its unzip there too, a link to ziptool until it
    // points here; the recovery binary is each of them.
    let (_, recovery) = paths::RECOVERY
        .rsplit_once('/')
        .expect("the recovery binary is in a folder");
    for command in paths::COMMANDS {
        rd.link(command, recovery)?;
    }
    rd.add(paths::SYSTEM_INIT, 0o755, read(files.system_init)?)?;
    rd.add(paths::CONFIG, 0o644, read(files.config)?)?;
    rd.add(paths::FONT, 0o644, read(files.font)?)?;
    rd.add(paths::MONO, 0o644, read(files.mono)?)?;
    rd.add(paths::MONO_LICENSE, 0o644, read(files.mono_license)?)?;
    // A photo of the phone beside its configuration, for the home page's
    // device card; a build whose device has none keeps the stock outline.
    let portrait = files.config.with_extension("png");
    if portrait.is_file() {
        rd.add(paths::PORTRAIT, 0o644, read(&portrait)?)?;
    }
    // A stock ramdisk may run logd without any scheduling profiles, and
    // logd stops as soon as it cannot find the one it asks for.
    if rd.find(paths::TASK_PROFILES).is_none() {
        rd.add(paths::TASK_PROFILES, 0o644, TASK_PROFILES.to_vec())?;
    }
    rd.add(paths::MTP_RC, 0o644, MTP_RC.to_vec())?;
    for extra in add {
        let (name, path) = extra
            .split_once('=')
            .with_context(|| format!("{extra} is not NAME=PATH"))?;
        ensure!(
            name.starts_with('/') && !name.ends_with('/'),
            "{name} is not a file's path in the ramdisk"
        );
        rd.add(name, 0o644, read(Path::new(path))?)?;
    }
    // On an unlocked device adbd keeps root when ro.secure is 0 and lets any
    // computer in without authorization when ro.adb.secure is 0; init lets a
    // later line of a property file override an earlier one. update_engine
    // refuses a package built before the recovery itself unless both of the
    // last two are set; the recovery checks packages against the installed
    // system instead.
    let stock_props = &rd
        .find(paths::PROP_DEFAULT)
        .with_context(|| format!("{} is not in the ramdisk", paths::PROP_DEFAULT))?
        .data;
    let mut props = without(stock_props, &BUILD_VERSION);
    if legacy_properties {
        props.extend_from_slice(
            b"\nro.secure=0\nro.adb.secure=0\nro.debuggable=1\nro.ota.allow_downgrade=true\n",
        );
    }
    rd.replace(paths::PROP_DEFAULT, props)?;

    if device == "xaga" {
        let policy = rd
            .find("sepolicy")
            .context("recovery ramdisk has no /sepolicy")?;
        // The loop worker reads the backing file opened by recovery.
        let patched = policy::allow(&policy.data, "kernel", "recovery", "fd", "use")?;
        rd.replace("sepolicy", patched)?;
    }
    Ok(())
}

fn write(out: &Path, img: &BootImage, bytes: &[u8]) -> Result<()> {
    std::fs::write(out, bytes).with_context(|| format!("write {}", out.display()))?;
    println!(
        "wrote {} ({} bytes kernel, {} bytes ramdisk, {} bytes in all)",
        out.display(),
        img.kernel.len(),
        img.ramdisk.len(),
        bytes.len()
    );
    Ok(())
}

fn list(image: &Path) -> Result<()> {
    let img = Image::read(image)?;
    match &img {
        Image::Boot(img) => println!(
            "boot image v{}  kernel {} bytes  ramdisk {} bytes  {:?}",
            img.header.header_version(),
            img.kernel.len(),
            img.ramdisk.len(),
            img.header.osversionpatch
        ),
        Image::Vendor(img) => println!(
            "vendor boot image v{}  ramdisk {} bytes  dtb {} bytes  {} fragment(s)  {} bytes of bootconfig",
            img.header.header_version(),
            img.ramdisk.len(),
            img.dtb.len(),
            img.table.len(),
            img.bootconfig.len()
        ),
    }
    if img.ramdisk().is_empty() {
        return Ok(());
    }
    let rd = Ramdisk::decode(img.ramdisk())?;
    for e in &rd.entries {
        println!(
            "{:06o} {:>5}:{:<5} {:>10}  {}",
            e.mode,
            e.uid,
            e.gid,
            e.data.len(),
            e.name
        );
    }
    println!("{} entries", rd.entries.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_direct_image_does_not_replace_output() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("image");
        std::fs::write(&out, b"existing").unwrap();
        let data = b"not an image";
        assert!(take_direct(&data[..], &"0".repeat(64), &out).is_err());
        assert!(take_direct(&data[..], &hex::encode(Sha256::digest(data)), &out).is_err());
        assert_eq!(std::fs::read(&out).unwrap(), b"existing");
    }

    #[test]
    fn the_lines_that_set_a_name_are_the_only_ones_left_out() {
        let props = b"ro.build.id=TQ\nro.build.version.release=13\nro.build.version.release_or_codename=13\nro.product.name=ishtar\n\
ro.vendor.build.security_patch=2026-10-01\nro.vendor.build.security_patch_level=1\n";
        let out = without(props, &BUILD_VERSION);
        let text = String::from_utf8(out).expect("property files are text");
        assert!(!text.contains("ro.build.version.release=13"));
        assert!(
            !text.contains("ro.vendor.build.security_patch=2026-10-01"),
            "the vendor partition's patch level is left out too"
        );
        assert!(
            text.contains("ro.build.version.release_or_codename=13"),
            "a longer name is left alone"
        );
        assert!(
            text.contains("ro.vendor.build.security_patch_level=1"),
            "a longer name is left alone"
        );
        assert!(text.contains("ro.build.id=TQ") && text.contains("ro.product.name=ishtar"));
    }

    #[test]
    fn the_profiles_name_all_the_recovery_asks_for() {
        let profiles: serde_json::Value =
            serde_json::from_slice(TASK_PROFILES).expect("the profiles are JSON");
        let names = |key: &str| -> Vec<String> {
            profiles[key]
                .as_array()
                .expect("a list")
                .iter()
                .map(|p| p["Name"].as_str().expect("a name").to_string())
                .collect()
        };
        let (plain, aggregate) = (names("Profiles"), names("AggregateProfiles"));
        // What libprocessgroup asks for when a program sets its scheduling
        // policy, and what the recovery's own init scripts give logd.
        let asked = [
            "SCHED_SP_DEFAULT",
            "SCHED_SP_BACKGROUND",
            "SCHED_SP_FOREGROUND",
            "SCHED_SP_TOP_APP",
            "SCHED_SP_SYSTEM",
            "SCHED_SP_RT_APP",
            "CPUSET_SP_DEFAULT",
            "CPUSET_SP_BACKGROUND",
            "CPUSET_SP_FOREGROUND",
            "CPUSET_SP_TOP_APP",
            "CPUSET_SP_SYSTEM",
            "CPUSET_SP_RESTRICTED",
            "BlkIOBackground",
            "BlkIOForeground",
            "ServiceCapacityLow",
        ];
        for name in asked {
            assert!(
                plain.iter().chain(&aggregate).any(|n| n == name),
                "{name} is missing"
            );
        }
        for a in profiles["AggregateProfiles"].as_array().expect("a list") {
            for part in a["Profiles"].as_array().expect("a list") {
                let part = part.as_str().expect("a name");
                assert!(
                    plain.iter().any(|n| n == part),
                    "{} is made of {part}, which is not a profile",
                    a["Name"]
                );
            }
        }
    }

    #[test]
    fn the_partition_is_as_large_as_a_stock_image_ending_in_its_footer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.img");
        let mut whole = vec![0u8; 8192];
        whole[8192 - 64..8192 - 60].copy_from_slice(b"AVBf");
        std::fs::write(&path, &whole).unwrap();
        assert_eq!(partition_size(&path).unwrap(), 8192);
        std::fs::write(&path, &whole[..8000]).unwrap();
        assert!(
            partition_size(&path).is_err(),
            "an image cut short of its partition's end"
        );
        std::fs::write(&path, b"AVBf").unwrap();
        assert!(
            partition_size(&path).is_err(),
            "too short to end in a footer"
        );
    }

    #[test]
    fn a_file_without_a_last_newline_keeps_its_last_line() {
        let out = without(b"a=1\nro.build.version.release=13", &BUILD_VERSION);
        assert_eq!(out, b"a=1\n");
        let kept = without(b"a=1\nb=2", &BUILD_VERSION);
        assert_eq!(kept, b"a=1\nb=2");
    }
}
