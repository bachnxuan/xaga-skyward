//! A newer build of Skyward, as its release zips it: the image in the zip,
//! checked to be Skyward for this phone, and the recovery partitions it
//! goes into, those of the slot that starts next and of any other slot
//! that holds Skyward.

use crate::image;
use anyhow::{ensure, Context, Result};
use skyward_vab::Slot;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

/// Whether a ZIP carries a vendor boot recovery fragment.
pub fn is_vendor_release(path: &Path) -> Result<bool> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut zip = zip::ZipArchive::new(file).context("read the ZIP")?;
    let present = zip.by_name("skyward/recovery.cpio").is_ok();
    Ok(present)
}

/// The image the zip at `path` holds, its only entry, read whole.
pub fn unzip(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut zip = zip::ZipArchive::new(file).with_context(|| format!("read {} as a zip", path.display()))?;
    if let Ok(mut entry) = zip.by_name("skyward/recovery.cpio") {
        ensure!(entry.size() > 0 && entry.size() <= 64 * 1024 * 1024, "invalid recovery fragment size");
        let mut recovery = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut recovery).context("unzip recovery fragment")?;
        return Ok(recovery);
    }
    ensure!(zip.len() == 1, "{} holds {} entries, and a release's zip holds its image alone", path.display(), zip.len());
    let mut entry = zip.by_index(0).context("open the image in the zip")?;
    ensure!(entry.name().ends_with(".img"), "the zip holds {}, which is not an image", entry.name());
    let mut image = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut image).context("unzip the image")?;
    Ok(image)
}

/// Check that `image` is Skyward, packed for the phone `codename` names.
pub fn check(image: &[u8], codename: &str) -> Result<()> {
    let config = if image.starts_with(b"ANDROID!") || image.starts_with(b"VNDRBOOT") {
        image::device_config(&mut Cursor::new(image))?
    } else {
        image::ramdisk_config(image)?
    }.context("the image is not Skyward")?;
    let config = std::str::from_utf8(&config).context("the image's device configuration is not text")?;
    let named = skyward_config::codename(config).context("read the image's device configuration")?;
    ensure!(named == codename, "the image is Skyward for {named}, not for {codename}");
    Ok(())
}

/// The slots whose recovery partition, among the links in `dir`, the newer
/// build goes into, slot A first: `next`, the slot that starts next, and
/// any other whose partition holds Skyward now, any build of it. `partition`
/// names the partition the recovery lives in.
pub fn slots(dir: &Path, next: Slot, partition: &str) -> Result<Vec<Slot>> {
    let mut slots = Vec::new();
    for slot in [Slot::A, Slot::B] {
        let path = image::device(dir, partition, slot);
        let mut file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
        image::drop_cache(&file).with_context(|| format!("drop the cached pages of {}", path.display()))?;
        if slot == next || image::is_skyward(&mut file).with_context(|| format!("look into {}", path.display()))? {
            slots.push(slot);
        }
    }
    Ok(slots)
}

/// Write `image` into the recovery partitions of `slots`, among the links
/// in `dir`, and read each back; `progress` hears the bytes so far, of all.
pub fn write(dir: &Path, image: &[u8], slots: &[Slot], partition: &str, progress: &mut dyn FnMut(u64, u64)) -> Result<()> {
    if partition == "vendor_boot" {
        ensure!(!image.starts_with(b"VNDRBOOT") && !image.starts_with(b"ANDROID!"), "vendor_boot update requires a recovery fragment, not a whole image");
        return write_vendor_boot(dir, image, slots, progress);
    }
    ensure!(image.starts_with(b"ANDROID!"), "dedicated recovery requires a boot image");
    let devices: Vec<PathBuf> = slots.iter().map(|&slot| image::device(dir, partition, slot)).collect();
    image::flash(&mut Cursor::new(image), image.len() as u64, &devices, progress)
}

/// Prepare every selected slot from its own installed vendor_boot before writing.
pub fn write_vendor_boot(dir: &Path, recovery: &[u8], slots: &[Slot], progress: &mut dyn FnMut(u64, u64)) -> Result<()> {
    use sha2::{Digest, Sha256};
    ensure!(!slots.is_empty(), "no partition to write");
    let mut prepared = Vec::new();
    for &slot in slots {
        let path = image::device(dir, "vendor_boot", slot);
        let file = std::fs::OpenOptions::new().read(true).write(true).open(&path).with_context(|| format!("open {} for writing", path.display()))?;
        image::drop_cache(&file)?;
        let mut base = Vec::new();
        file.take((64 * 1024 * 1024 + 1) as u64).read_to_end(&mut base)?;
        ensure!(base.len() <= 64 * 1024 * 1024, "{} exceeds 64 MiB", path.display());
        let (output, _) = skyward_bootimg::VendorBootImage::prepare(&base, recovery)
            .with_context(|| format!("prepare {}", path.display()))?;
        let output = skyward_bootimg::avb::footed(&output, "vendor_boot", base.len(), &Sha256::digest(&output))?;
        prepared.push((path, output));
    }
    let total = prepared.iter().map(|(_, bytes)| 2 * bytes.len() as u64).sum();
    let mut completed = 0;
    for (path, output) in prepared {
        image::flash(&mut Cursor::new(&output), output.len() as u64, &[path], &mut |done, _| progress(completed + done, total))?;
        completed += 2 * output.len() as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::samples::{recovery, skyward_for};
    use std::io::Write;

    /// A zip of `entries`, each a name and what it holds.
    fn zipped(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut zip = zip::ZipWriter::new(file.reopen().unwrap());
        for (name, data) in entries {
            zip.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
        file
    }

    #[test]
    fn the_image_in_a_releases_zip_is_taken_whole() {
        let image = skyward_for("ishtar");
        let zip = zipped(&[("skyward-v0.1.4-ishtar-OS3.0.308.0.WMACNXM.img", &image)]);
        assert_eq!(unzip(zip.path()).unwrap(), image);
        let two = zipped(&[("a.img", &image), ("b.img", &image)]);
        assert!(unzip(two.path()).is_err(), "a zip with more than the image");
        let other = zipped(&[("notes.txt", b"not an image")]);
        assert!(unzip(other.path()).is_err());
        let unzipped = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(unzipped.path(), &image).unwrap();
        assert!(unzip(unzipped.path()).is_err(), "an image that is not zipped");
    }

    #[test]
    fn only_skyward_for_this_phone_goes_in() {
        assert!(check(&skyward_for("ishtar"), "ishtar").is_ok());
        let e = check(&skyward_for("nezha"), "ishtar").unwrap_err();
        assert_eq!(e.to_string(), "the image is Skyward for nezha, not for ishtar");
        assert_eq!(check(&recovery(false), "ishtar").unwrap_err().to_string(), "the image is not Skyward");
        assert!(check(&recovery(true), "ishtar").is_err(), "a device configuration that names no phone");
    }

    /// Recovery partitions of `size` bytes holding `a` and `b`.
    fn partitions(a: &[u8], b: &[u8], size: usize) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, image) in [("recovery_a", a), ("recovery_b", b)] {
            let mut bytes = image.to_vec();
            bytes.resize(size, 0);
            std::fs::write(dir.path().join(name), bytes).unwrap();
        }
        dir
    }

    #[test]
    fn the_build_goes_where_the_phone_starts_next_and_where_skyward_is() {
        let (skyward, stock) = (skyward_for("ishtar"), recovery(false));
        let size = skyward.len().max(stock.len()) + 4096;
        assert_eq!(slots(partitions(&skyward, &stock, size).path(), Slot::A, "recovery").unwrap(), [Slot::A]);
        assert_eq!(slots(partitions(&skyward, &skyward, size).path(), Slot::A, "recovery").unwrap(), [Slot::A, Slot::B], "an older build in the other slot");
        assert_eq!(slots(partitions(&stock, &skyward, size).path(), Slot::A, "recovery").unwrap(), [Slot::A, Slot::B], "Skyward started without being flashed");
        assert_eq!(slots(partitions(&stock, &stock, size).path(), Slot::B, "recovery").unwrap(), [Slot::B]);
    }

    #[test]
    fn the_build_is_written_and_read_back() {
        let (older, newer, stock) = (recovery(true), skyward_for("ishtar"), recovery(false));
        let size = older.len().max(newer.len()) + 4096;
        let dir = partitions(&older, &stock, size);
        let mut told = Vec::new();
        write(dir.path(), &newer, &[Slot::A], "recovery", &mut |done, total| told.push((done, total))).unwrap();
        let total = 2 * newer.len() as u64;
        assert_eq!(told.last(), Some(&(total, total)), "written and read back");
        assert_eq!(&std::fs::read(dir.path().join("recovery_a")).unwrap()[..newer.len()], &newer[..]);
        assert_eq!(&std::fs::read(dir.path().join("recovery_b")).unwrap()[..stock.len()], &stock[..], "the other slot left alone");
    }
    #[test]
    fn vendor_slots_are_prepared_independently_before_writing() {
        use abootimg_oxide::{VendorHeader, VendorHeaderV4};
        use skyward_bootimg::{BootImage, TableEntry, VendorBootImage};
        let dir = tempfile::tempdir().unwrap();
        for (slot, id) in [("a", 1u8), ("b", 2)] {
            let image = VendorBootImage {
                header: VendorHeader {
                    page_size: 4096, kernel_addr: id as u32, ramdisk_addr: 0,
                    vendor_ramdisk_size: 4, cmdline: Box::new([0; 2048]), tags_addr: 0,
                    board_name: [id; 16], dtb_size: 1, dtb_addr: 0,
                    v4: Some(VendorHeaderV4 {
                        vendor_ramdisk_table_size: 108, vendor_ramdisk_table_entry_num: 1,
                        vendor_ramdisk_table_entry_size: 108, bootconfig_size: 1,
                    }),
                },
                ramdisk: vec![id; 4], dtb: vec![id], bootconfig: vec![id],
                table: vec![TableEntry { size: 4, offset: 0, kind: 1, name: [0; 32], board_id: [[id; 16]; 4] }],
            };
            let mut bytes = image.to_bytes().unwrap();
            bytes.resize(65536, 0);
            std::fs::write(dir.path().join(format!("vendor_boot_{slot}")), bytes).unwrap();
        }
        let original_b = std::fs::read(dir.path().join("vendor_boot_b")).unwrap();
        let payload = BootImage::parse(&skyward_for("xaga")).unwrap().ramdisk;
        let zip = zipped(&[("META-INF/com/google/android/update-binary", b"binary"), ("skyward/recovery.cpio", &payload)]);
        assert!(is_vendor_release(zip.path()).unwrap());
        assert_eq!(crate::package::identify(std::fs::File::open(zip.path()).unwrap()).unwrap(), crate::package::Package::Script);
        let unpacked = unzip(zip.path()).unwrap();
        check(&unpacked, "xaga").unwrap();
        assert!(check(&unpacked, "other").is_err());
        write_vendor_boot(dir.path(), &unpacked, &[Slot::A, Slot::B], &mut |_, _| {}).unwrap();
        for (slot, id) in [("a", 1u8), ("b", 2)] {
            let bytes = std::fs::read(dir.path().join(format!("vendor_boot_{slot}"))).unwrap();
            let image = VendorBootImage::parse(&bytes).unwrap();
            assert_eq!(&image.ramdisk[..4], &[id; 4]);
            assert_eq!(image.dtb, [id]);
            assert_eq!(image.bootconfig, [id]);
            assert_eq!(image.table[0].board_id, [[id; 16]; 4]);
            assert_eq!(image.recovery().unwrap(), Some(&payload[..]));
            assert!(crate::image::is_skyward(&mut Cursor::new(bytes)).unwrap());
        }
        let kept = crate::keep::Kept::hold(dir.path(), Slot::A, "vendor_boot").unwrap().unwrap();
        assert!(kept.wanted(Slot::B).unwrap().is_empty());
        std::fs::write(dir.path().join("vendor_boot_b"), original_b).unwrap();
        assert_eq!(kept.wanted(Slot::B).unwrap(), [Slot::B]);
        kept.write(&[Slot::B], &mut |_, _| {}).unwrap();
        let restored = VendorBootImage::parse(&std::fs::read(dir.path().join("vendor_boot_b")).unwrap()).unwrap();
        assert_eq!(restored.dtb, [2]);
        assert_eq!(&restored.ramdisk[..4], &[2; 4]);
        assert_eq!(restored.recovery().unwrap(), Some(payload.as_slice()));
        let a = std::fs::read(dir.path().join("vendor_boot_a")).unwrap();
        std::fs::write(dir.path().join("vendor_boot_b"), b"broken").unwrap();
        assert!(write_vendor_boot(dir.path(), &payload, &[Slot::A, Slot::B], &mut |_, _| {}).is_err());
        assert_eq!(std::fs::read(dir.path().join("vendor_boot_a")).unwrap(), a);
    }
}
