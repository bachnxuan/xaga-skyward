//! The footer a recovery image ends in for the bootloader to verify it by:
//! an unsigned vbmeta image holding the image's digest, laid out over the
//! whole partition as avbtool's `add_hash_footer --algorithm NONE` lays it.
//! An unlocked bootloader boots such an image whatever its digest; it gives
//! up on the whole slot when the footer at the partition's end points at
//! anything but a vbmeta image, as a stock footer left behind an image
//! written over the start of the partition does.

use abootimg_oxide::binrw::{BinRead, io::Cursor};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

/// The unit avbtool lays an image and its vbmeta image out in.
const BLOCK: usize = 4096;
const FOOTER_LEN: usize = 64;
const HEADER_LEN: usize = 256;
const TAG_HASH: u64 = 2;
const RELEASE: &[u8] = b"skyward-pack";

/// Find the image before its AVB metadata without checking its old digest.
pub(crate) fn image_end(base: &[u8]) -> Result<Option<usize>> {
    let Some(at) = base.len().checked_sub(FOOTER_LEN) else {
        return Ok(None);
    };
    let footer = &base[at..];
    if !footer.starts_with(b"AVBf") {
        return Ok(None);
    }
    ensure!(
        u32::read_be(&mut Cursor::new(&footer[4..]))? == 1,
        "unsupported AVB footer version"
    );
    let mut fields = Cursor::new(&footer[12..]);
    let original = usize::try_from(u64::read_be(&mut fields)?)?;
    let offset = usize::try_from(u64::read_be(&mut fields)?)?;
    let size = usize::try_from(u64::read_be(&mut fields)?)?;
    let end = offset.checked_add(size).context("AVB metadata end")?;
    ensure!(
        original <= offset && size >= HEADER_LEN && end <= at,
        "invalid AVB footer bounds"
    );
    ensure!(
        base[original..offset]
            .iter()
            .chain(&base[end..at])
            .all(|&b| b == 0),
        "unrecognized nonzero data outside AVB metadata"
    );

    let meta = &base[offset..end];
    ensure!(meta.starts_with(b"AVB0"), "invalid AVB metadata magic");
    let mut blocks = Cursor::new(&meta[12..]);
    let auth = usize::try_from(u64::read_be(&mut blocks)?)?;
    let aux = usize::try_from(u64::read_be(&mut blocks)?)?;
    let aux_start = HEADER_LEN
        .checked_add(auth)
        .context("AVB authentication size")?;
    ensure!(
        aux_start.checked_add(aux) == Some(size),
        "invalid AVB block sizes"
    );
    let mut fields = Cursor::new(&meta[96..]);
    let desc_offset = usize::try_from(u64::read_be(&mut fields)?)?;
    let desc_size = usize::try_from(u64::read_be(&mut fields)?)?;
    let desc_end = desc_offset
        .checked_add(desc_size)
        .context("AVB descriptors end")?;
    ensure!(desc_end <= aux, "invalid AVB descriptor bounds");
    let mut descriptors = &meta[aux_start + desc_offset..aux_start + desc_end];
    while !descriptors.is_empty() {
        ensure!(descriptors.len() >= 16, "truncated AVB descriptor");
        let size = usize::try_from(u64::read_be(&mut Cursor::new(&descriptors[8..]))?)?;
        let end = 16usize.checked_add(size).context("AVB descriptor end")?;
        ensure!(
            size % 8 == 0 && end <= descriptors.len(),
            "invalid AVB descriptor size"
        );
        descriptors = &descriptors[end..];
    }
    Ok(Some(original))
}

/// `image` grown to fill a `partition_size`-byte partition named
/// `partition`: the image, its vbmeta image from the next block on, and the
/// footer locating that in the partition's last bytes, zeros between.
pub fn footed(
    image: &[u8],
    partition: &str,
    partition_size: usize,
    salt: &[u8],
) -> Result<Vec<u8>> {
    let digest = Sha256::new()
        .chain_update(salt)
        .chain_update(image)
        .finalize();
    let vbmeta = vbmeta(&hash_descriptor(
        image.len() as u64,
        partition,
        salt,
        &digest,
    ));
    let offset = image.len().next_multiple_of(BLOCK);
    let end = offset + vbmeta.len().next_multiple_of(BLOCK);
    ensure!(
        end + BLOCK <= partition_size,
        "a {}-byte image and its vbmeta image do not fit a {partition_size}-byte {partition} partition beside its footer",
        image.len()
    );
    let mut out = Vec::with_capacity(partition_size);
    out.extend_from_slice(image);
    out.resize(offset, 0);
    out.extend_from_slice(&vbmeta);
    out.resize(partition_size - FOOTER_LEN, 0);
    out.extend_from_slice(b"AVBf");
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    for n in [image.len(), offset, vbmeta.len()] {
        out.extend_from_slice(&(n as u64).to_be_bytes());
    }
    out.resize(partition_size, 0);
    Ok(out)
}

/// A descriptor saying the first `image_size` bytes of `partition`, salted
/// with `salt`, hash to `digest` under SHA-256.
fn hash_descriptor(image_size: u64, partition: &str, salt: &[u8], digest: &[u8]) -> Vec<u8> {
    let mut algorithm = [0u8; 32];
    algorithm[..6].copy_from_slice(b"sha256");
    let mut d = Vec::new();
    d.extend_from_slice(&TAG_HASH.to_be_bytes());
    // How many bytes follow these first sixteen, once they are known.
    d.extend_from_slice(&0u64.to_be_bytes());
    d.extend_from_slice(&image_size.to_be_bytes());
    d.extend_from_slice(&algorithm);
    // The lengths of the name, salt and digest, then the flags.
    for n in [partition.len(), salt.len(), digest.len(), 0] {
        d.extend_from_slice(&(n as u32).to_be_bytes());
    }
    d.extend_from_slice(&[0; 60]);
    d.extend_from_slice(partition.as_bytes());
    d.extend_from_slice(salt);
    d.extend_from_slice(digest);
    d.resize(d.len().next_multiple_of(8), 0);
    let following = (d.len() - 16) as u64;
    d[8..16].copy_from_slice(&following.to_be_bytes());
    d
}

/// An unsigned vbmeta image holding `descriptors`: its header, an empty
/// authentication block and the descriptors as its auxiliary block.
fn vbmeta(descriptors: &[u8]) -> Vec<u8> {
    let aux = descriptors.len().next_multiple_of(64);
    let mut v = Vec::with_capacity(HEADER_LEN + aux);
    v.extend_from_slice(b"AVB0");
    // The libavb version it needs, 1.0.
    v.extend_from_slice(&1u32.to_be_bytes());
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&0u64.to_be_bytes());
    v.extend_from_slice(&(aux as u64).to_be_bytes());
    // No signing algorithm.
    v.extend_from_slice(&0u32.to_be_bytes());
    // The offsets and sizes of the hash, the signature, the public key, its
    // metadata and the descriptors, then the rollback index.
    let n = descriptors.len();
    for field in [0, 0, 0, 0, n, 0, n, 0, 0, n, 0] {
        v.extend_from_slice(&(field as u64).to_be_bytes());
    }
    // The flags and the rollback index location.
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(RELEASE);
    v.resize(HEADER_LEN, 0);
    v.extend_from_slice(descriptors);
    v.resize(HEADER_LEN + aux, 0);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; 32] = [0x5a; 32];

    /// What avbtool 1.4.0 makes of `len` bytes of `S`, given by
    /// `add_hash_footer --partition_size 81920 --partition_name recovery
    /// --algorithm NONE --salt 5a…5a --internal_release_string skyward-pack`.
    fn avbtool(len: usize) -> &'static [u8] {
        match len {
            4096 => include_bytes!("../../skyward-pack/tests/avb-footer-4096.bin"),
            1000 => include_bytes!("../../skyward-pack/tests/avb-footer-1000.bin"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn the_footer_is_avbtools_byte_for_byte() {
        for len in [4096, 1000] {
            let got = footed(&vec![b'S'; len], "recovery", 81920, &SALT).unwrap();
            assert!(got == avbtool(len), "a {len}-byte image");
        }
    }

    #[test]
    fn footer_layout_rejects_truncation_overflow_and_unknown_image_data() {
        let base = footed(&vec![b'S'; 1000], "vendor_boot", 81920, &SALT).unwrap();
        assert_eq!(image_end(&base).unwrap(), Some(1000));
        assert_eq!(image_end(b"not an AVB image").unwrap(), None);
        let footer = base.len() - FOOTER_LEN;
        for (at, value) in [
            (footer + 12, 81920),
            (footer + 20, u64::MAX),
            (footer + 28, u64::MAX),
            (4096 + 12, u64::MAX),
            (4096 + 20, u64::MAX),
            (4096 + 96, u64::MAX),
            (4096 + 104, u64::MAX),
            (4096 + HEADER_LEN + 8, u64::MAX),
            (4096 + HEADER_LEN + 8, 1),
        ] {
            let mut broken = base.clone();
            broken[at..at + 8].copy_from_slice(&value.to_be_bytes());
            assert!(image_end(&broken).is_err(), "field at {at}");
        }
        for at in [1000, 81920 - FOOTER_LEN - 1] {
            let mut broken = base.clone();
            broken[at] = 1;
            assert!(image_end(&broken).is_err(), "unknown byte at {at}");
        }
        for len in [0, 3, 63, 64] {
            assert_eq!(image_end(&base[..len]).unwrap(), None);
        }
    }

    #[test]
    fn descriptor_tags_do_not_limit_footer_removal() {
        let mut base = footed(&vec![b'S'; 1000], "vendor_boot", 81920, &SALT).unwrap();
        base[4096 + HEADER_LEN..4096 + HEADER_LEN + 8].copy_from_slice(&99u64.to_be_bytes());
        assert_eq!(image_end(&base).unwrap(), Some(1000));
    }

    #[test]
    fn an_image_that_leaves_no_room_for_its_vbmeta_and_footer_is_refused() {
        let image = vec![b'S'; 8192];
        assert!(
            footed(&image, "recovery", 16384, &SALT).is_ok(),
            "a block each for the vbmeta image and the footer"
        );
        assert!(footed(&image, "recovery", 12288, &SALT).is_err());
    }
}
