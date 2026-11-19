//! A vendor boot image with header version 3 or 4 (`vendor_boot`): its
//! header, vendor ramdisk, device tree and, from version 4, its table of
//! ramdisk fragments and its bootconfig. Read, changed and written again by
//! the image packer, for phones whose recovery rides in the vendor boot
//! image instead of a recovery partition of its own.

use abootimg_oxide::VendorHeader;
use abootimg_oxide::binrw::io::Cursor;
use abootimg_oxide::binrw::{BinRead, BinWrite};
use anyhow::{Context, Result, ensure};
use std::fs;
use std::path::Path;

/// One entry of a version 4 vendor boot image's ramdisk table: where a
/// fragment of the vendor ramdisk lies, what kind it is and which boards it
/// is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableEntry {
    pub size: u32,
    pub offset: u32,
    /// 1 for platform, 2 for recovery, 3 for DLKM.
    pub kind: u32,
    pub name: [u8; 32],
    pub board_id: [[u8; 16]; 4],
}

/// The length of a table entry as the format lays it out.
const ENTRY_LEN: usize = 4 + 4 + 4 + 32 + 4 * 16;

fn section(bytes: &[u8], at: usize, len: u32, what: &str) -> Result<Vec<u8>> {
    let end = at.checked_add(len as usize).context("section end")?;
    bytes
        .get(at..end)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| anyhow::anyhow!("{what} runs past the end of the image"))
}

fn pad(out: &mut Vec<u8>, page: usize) {
    out.resize(out.len().div_ceil(page) * page, 0);
}

impl TableEntry {
    fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= ENTRY_LEN,
            "a vendor ramdisk table entry is {} bytes",
            bytes.len()
        );
        let read =
            |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"));
        let mut name = [0u8; 32];
        name.copy_from_slice(&bytes[12..44]);
        let mut board_id = [[0u8; 16]; 4];
        for (n, board) in board_id.iter_mut().enumerate() {
            board.copy_from_slice(&bytes[44 + n * 16..60 + n * 16]);
        }
        Ok(TableEntry {
            size: read(0),
            offset: read(4),
            kind: read(8),
            name,
            board_id,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.extend_from_slice(&self.kind.to_le_bytes());
        out.extend_from_slice(&self.name);
        for board in &self.board_id {
            out.extend_from_slice(board);
        }
    }
}

/// A vendor boot image, split into its header and the sections the header
/// locates.
pub struct VendorBootImage {
    pub header: VendorHeader,
    pub ramdisk: Vec<u8>,
    pub dtb: Vec<u8>,
    pub table: Vec<TableEntry>,
    pub bootconfig: Vec<u8>,
}

impl VendorBootImage {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        VendorBootImage::parse(&bytes).with_context(|| format!("read {}", path.display()))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let header = VendorHeader::read(&mut Cursor::new(bytes)).context("header")?;
        ensure!(
            header.page_size.is_power_of_two() && header.page_size >= 512,
            "page size {}",
            header.page_size
        );
        let ramdisk = section(
            bytes,
            header.ramdisk_position(),
            header.vendor_ramdisk_size,
            "vendor ramdisk",
        )?;
        let dtb = section(bytes, header.dtb_position(), header.dtb_size, "dtb")?;
        let (table, bootconfig) = match &header.v4 {
            None => (Vec::new(), Vec::new()),
            Some(v4) => {
                let entry = v4.vendor_ramdisk_table_entry_size as usize;
                ensure!(
                    entry == ENTRY_LEN,
                    "unsupported vendor ramdisk table entry size {entry}"
                );
                let count = v4.vendor_ramdisk_table_entry_num as usize;
                ensure!(
                    count <= 64
                        && count.checked_mul(entry) == Some(v4.vendor_ramdisk_table_size as usize),
                    "invalid vendor ramdisk table dimensions"
                );
                let raw = section(
                    bytes,
                    header.ramdisk_table_position(),
                    v4.vendor_ramdisk_table_size,
                    "vendor ramdisk table",
                )?;
                let mut table = Vec::with_capacity(count);
                for n in 0..v4.vendor_ramdisk_table_entry_num as usize {
                    table.push(TableEntry::parse(&raw[n * entry..])?);
                }
                let at = header
                    .bootconfig_position()
                    .expect("a version 4 header has a bootconfig position");
                (table, section(bytes, at, v4.bootconfig_size, "bootconfig")?)
            }
        };
        let image = VendorBootImage {
            header,
            ramdisk,
            dtb,
            table,
            bootconfig,
        };
        if image.header.v4.is_some() {
            image.validate_fragments()?;
        }
        Ok(image)
    }

    fn validate_fragments(&self) -> Result<()> {
        let mut offset = 0usize;
        let mut names = std::collections::HashSet::new();
        let mut recovery = false;
        for entry in &self.table {
            ensure!(
                entry.kind <= 3,
                "unsupported vendor ramdisk fragment type {}",
                entry.kind
            );
            let end = entry
                .name
                .iter()
                .position(|&b| b == 0)
                .context("unterminated fragment name")?;
            ensure!(
                entry.name[end..].iter().all(|&b| b == 0),
                "invalid fragment name padding"
            );
            let name = &entry.name[..end];
            ensure!(
                name.iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(b)),
                "invalid fragment name"
            );
            ensure!(names.insert(name), "duplicate vendor ramdisk fragment name");
            if entry.kind == 2 || name == b"recovery" {
                ensure!(
                    entry.kind == 2 && name == b"recovery" && !recovery,
                    "ambiguous recovery fragment"
                );
                recovery = true;
            }
            ensure!(
                entry.size != 0 && entry.offset as usize == offset,
                "noncontiguous or empty vendor ramdisk fragment"
            );
            offset = offset
                .checked_add(entry.size as usize)
                .context("fragment end")?;
            ensure!(
                offset <= self.ramdisk.len(),
                "vendor ramdisk fragment exceeds section"
            );
        }
        ensure!(
            offset == self.ramdisk.len(),
            "vendor ramdisk is not fully described by its table"
        );
        Ok(())
    }

    /// The type-2 recovery fragment, if present.
    pub fn recovery(&self) -> Result<Option<&[u8]>> {
        ensure!(
            self.header.v4.is_some(),
            "recovery fragments require vendor boot v4"
        );
        self.validate_fragments()?;
        Ok(self
            .table
            .iter()
            .find(|e| e.kind == 2)
            .map(|e| &self.ramdisk[e.offset as usize..e.offset as usize + e.size as usize]))
    }

    /// Replace or append a recovery fragment without changing the other fragments.
    pub fn replace_recovery(&mut self, recovery: &[u8]) -> Result<()> {
        ensure!(
            self.header.v4.is_some(),
            "recovery fragments require vendor boot v4"
        );
        ensure!(!recovery.is_empty(), "empty recovery fragment");
        self.validate_fragments()?;
        let old_size = self
            .table
            .iter()
            .find(|e| e.kind == 2)
            .map_or(0, |e| e.size as usize);
        let new_len = self
            .ramdisk
            .len()
            .checked_sub(old_size)
            .and_then(|n| n.checked_add(recovery.len()))
            .context("vendor ramdisk size")?;
        ensure!(new_len <= 64 * 1024 * 1024, "vendor ramdisk exceeds 64 MiB");
        let index = match self.table.iter().position(|e| e.kind == 2) {
            Some(index) => index,
            None => {
                ensure!(self.table.len() < 64, "too many vendor ramdisk fragments");
                let mut name = [0; 32];
                name[..8].copy_from_slice(b"recovery");
                self.table.push(TableEntry {
                    size: 0,
                    offset: self.ramdisk.len() as u32,
                    kind: 2,
                    name,
                    board_id: [[0; 16]; 4],
                });
                self.table.len() - 1
            }
        };
        let start = self.table[index].offset as usize;
        let end = start + self.table[index].size as usize;
        self.ramdisk.splice(start..end, recovery.iter().copied());
        self.table[index].size = u32::try_from(recovery.len()).context("recovery size")?;
        let mut offset = 0u32;
        for entry in &mut self.table {
            entry.offset = offset;
            offset = offset
                .checked_add(entry.size)
                .context("vendor ramdisk size")?;
        }
        self.validate_fragments()
    }

    /// Prepare an unsigned v4 image. Full-partition writes need a new AVB footer.
    pub fn prepare(base: &[u8], recovery: &[u8]) -> Result<(Vec<u8>, bool)> {
        let avb_end = crate::avb::image_end(base)?;
        let base = &base[..avb_end.unwrap_or(base.len())];
        let mut image = Self::parse(base)?;
        let serialized = image.to_bytes()?;
        ensure!(
            base.starts_with(&serialized),
            "vendor_boot cannot be reconstructed losslessly"
        );
        ensure!(
            base[serialized.len()..].iter().all(|&b| b == 0),
            "unrecognized nonzero data after vendor_boot sections"
        );
        image.replace_recovery(recovery)?;
        Ok((image.to_bytes()?, avb_end.is_some()))
    }

    /// The image with its ramdisk replaced by `ramdisk`, every other section
    /// as it was: one fragment of the same kind as the one the stock image
    /// carried, when it carried one.
    pub fn with_ramdisk(&self, ramdisk: Vec<u8>) -> Result<Self> {
        ensure!(
            self.table.len() <= 1,
            "the vendor boot image carries {} ramdisk fragments, and this packer replaces one",
            self.table.len()
        );
        let mut table = self.table.clone();
        match table.first_mut() {
            Some(entry) => {
                entry.size = u32::try_from(ramdisk.len()).context("vendor ramdisk size")?;
                entry.offset = 0;
            }
            None => table.push(TableEntry {
                size: ramdisk.len() as u32,
                offset: 0,
                kind: 1,
                name: [0; 32],
                board_id: [[0; 16]; 4],
            }),
        }
        Ok(VendorBootImage {
            header: self.header.clone(),
            ramdisk,
            dtb: self.dtb.clone(),
            table,
            bootconfig: self.bootconfig.clone(),
        })
    }

    /// The image as the partition holds it before its AVB footer.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let page = self.header.page_size as usize;
        let mut header = self.header.clone();
        header.vendor_ramdisk_size =
            u32::try_from(self.ramdisk.len()).context("vendor ramdisk size")?;
        if let Some(v4) = &mut header.v4 {
            v4.vendor_ramdisk_table_entry_num =
                u32::try_from(self.table.len()).context("table entries")?;
            v4.vendor_ramdisk_table_entry_size = ENTRY_LEN as u32;
            v4.vendor_ramdisk_table_size =
                u32::try_from(self.table.len() * ENTRY_LEN).context("table size")?;
            v4.bootconfig_size = u32::try_from(self.bootconfig.len()).context("bootconfig size")?;
        }
        let mut writer = Cursor::new(Vec::new());
        header.write(&mut writer).context("write header")?;
        let mut out = writer.into_inner();
        pad(&mut out, page);
        out.extend_from_slice(&self.ramdisk);
        pad(&mut out, page);
        out.extend_from_slice(&self.dtb);
        pad(&mut out, page);
        if self.header.v4.is_some() {
            let mut table = Vec::with_capacity(self.table.len() * ENTRY_LEN);
            for entry in &self.table {
                entry.write(&mut table);
            }
            out.extend_from_slice(&table);
            pad(&mut out, page);
            out.extend_from_slice(&self.bootconfig);
            pad(&mut out, page);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A version 4 vendor boot image with `ramdisk` as its one fragment and
    /// `dtb` as its device tree, laid out as the format lays it out.
    fn image(ramdisk: &[u8], dtb: &[u8]) -> Vec<u8> {
        let header = VendorHeader {
            page_size: 4096,
            kernel_addr: 0,
            ramdisk_addr: 0,
            vendor_ramdisk_size: ramdisk.len() as u32,
            cmdline: Box::new([0; 2048]),
            tags_addr: 0,
            board_name: [0; 16],
            dtb_size: dtb.len() as u32,
            dtb_addr: 0,
            v4: Some(abootimg_oxide::VendorHeaderV4 {
                vendor_ramdisk_table_size: ENTRY_LEN as u32,
                vendor_ramdisk_table_entry_num: 1,
                vendor_ramdisk_table_entry_size: ENTRY_LEN as u32,
                bootconfig_size: 0,
            }),
        };
        let mut writer = Cursor::new(Vec::new());
        header.write(&mut writer).unwrap();
        let mut out = writer.into_inner();
        pad(&mut out, 4096);
        out.extend_from_slice(ramdisk);
        pad(&mut out, 4096);
        out.extend_from_slice(dtb);
        pad(&mut out, 4096);
        let mut name = [0; 32];
        name[..8].copy_from_slice(b"recovery");
        let entry = TableEntry {
            size: ramdisk.len() as u32,
            offset: 0,
            kind: 2,
            name,
            board_id: [[0; 16]; 4],
        };
        entry.write(&mut out);
        pad(&mut out, 4096);
        out
    }

    #[test]
    fn a_vendor_boot_image_keeps_its_dtb_and_its_fragment_kind() {
        let dtb = b"dtb";
        let stock = image(b"stock ramdisk", dtb);
        let image = VendorBootImage::parse(&stock).unwrap();
        assert_eq!(image.ramdisk, b"stock ramdisk");
        assert_eq!(image.dtb, dtb);
        assert_eq!(image.table[0].kind, 2, "a recovery fragment stays one");
        let rebuilt = image.with_ramdisk(b"skyward".to_vec()).unwrap();
        let parsed = VendorBootImage::parse(&rebuilt.to_bytes().unwrap()).unwrap();
        assert_eq!(parsed.ramdisk, b"skyward");
        assert_eq!(parsed.dtb, dtb);
        assert_eq!(parsed.table[0].size, 7);
        assert_eq!(parsed.table[0].offset, 0);
        assert_eq!(parsed.header.vendor_ramdisk_size, 7);
    }

    #[test]
    fn an_image_with_more_than_one_fragment_is_refused() {
        let mut image = VendorBootImage::parse(&image(b"ramdisk", b"dtb")).unwrap();
        image.table.push(image.table[0].clone());
        assert!(image.with_ramdisk(b"skyward".to_vec()).is_err());
    }
    #[test]
    fn recovery_merge_preserves_platform_dlkm_and_slot_metadata() {
        for id in [11u8, 22] {
            let mut image = VendorBootImage::parse(&image(b"platform", &[id])).unwrap();
            image.table[0].kind = 1;
            image.table[0].name = [0; 32];
            image.table[0].board_id[0][0] = id;
            let mut name = [0; 32];
            name[..4].copy_from_slice(b"dlkm");
            image.table.push(TableEntry {
                size: 4,
                offset: 8,
                kind: 3,
                name,
                board_id: [[id; 16]; 4],
            });
            image.ramdisk.extend_from_slice(b"mods");
            image.bootconfig = vec![id, 2];
            let base = image.to_bytes().unwrap();
            let (out, _) = VendorBootImage::prepare(&base, b"new recovery").unwrap();
            let parsed = VendorBootImage::parse(&out).unwrap();
            assert_eq!(&parsed.ramdisk[..12], b"platformmods");
            assert_eq!(parsed.table[1].kind, 3);
            assert_eq!(parsed.table[1].board_id, [[id; 16]; 4]);
            assert_eq!(parsed.table[0].board_id[0][0], id);
            assert_eq!(parsed.dtb, vec![id]);
            assert_eq!(parsed.bootconfig, vec![id, 2]);
            assert_eq!(parsed.recovery().unwrap(), Some(&b"new recovery"[..]));
            let (again, _) = VendorBootImage::prepare(&out, b"new recovery").unwrap();
            assert_eq!(out, again);
            assert!(VendorBootImage::prepare(&base, b"").is_err());
        }
    }
    #[test]
    fn stale_hash_and_property_keep_current_sections() {
        let mut current = VendorBootImage::parse(&image(b"platform", b"dtb")).unwrap();
        current.table[0].kind = 1;
        current.table[0].name = [0; 32];
        current.replace_recovery(&vec![0x5a; 8192]).unwrap();
        current.bootconfig = b"androidboot.test=1\n".to_vec();
        let unsigned = current.to_bytes().unwrap();
        let mut base = crate::avb::footed(&unsigned, "vendor_boot", 81920, &[0x5a; 64]).unwrap();
        let meta = unsigned.len();
        let hash = meta + 256;
        base[hash + 16..hash + 24].copy_from_slice(&4096u64.to_be_bytes());

        let key = b"com.android.build.vendor_boot.fingerprint";
        let value = b"test/device/product:16/build/version:userdebug/release-keys";
        let mut property = Vec::new();
        for n in [0, 0, key.len() as u64, value.len() as u64] {
            property.extend_from_slice(&n.to_be_bytes());
        }
        property.extend_from_slice(key);
        property.push(0);
        property.extend_from_slice(value);
        property.push(0);
        property.resize(property.len().next_multiple_of(8), 0);
        let following = (property.len() - 16) as u64;
        property[8..16].copy_from_slice(&following.to_be_bytes());
        let old_len = u64::from_be_bytes(base[meta + 104..meta + 112].try_into().unwrap()) as usize;
        base[hash + old_len..hash + old_len + property.len()].copy_from_slice(&property);
        let desc_len = old_len + property.len();
        let aux_len = desc_len.next_multiple_of(64);
        base[meta + 20..meta + 28].copy_from_slice(&(aux_len as u64).to_be_bytes());
        base[meta + 104..meta + 112].copy_from_slice(&(desc_len as u64).to_be_bytes());
        let footer = base.len() - 64;
        base[footer + 28..footer + 36].copy_from_slice(&((256 + aux_len) as u64).to_be_bytes());

        let (out, stripped) = VendorBootImage::prepare(&base, b"replacement").unwrap();
        assert!(stripped);
        let parsed = VendorBootImage::parse(&out).unwrap();
        assert_eq!(&parsed.ramdisk[..8], b"platform");
        assert_eq!(parsed.recovery().unwrap(), Some(&b"replacement"[..]));
        assert_eq!(parsed.dtb, current.dtb);
        assert_eq!(parsed.bootconfig, current.bootconfig);

        base[unsigned.len() - 1] = 1;
        assert!(VendorBootImage::prepare(&base, b"replacement").is_err());
    }

    #[test]
    fn malformed_or_ambiguous_fragment_layouts_are_rejected() {
        let mut base = image(b"ramdisk", b"dtb");
        base[12288 + 8..12288 + 12].copy_from_slice(&3u32.to_le_bytes());
        assert!(VendorBootImage::prepare(&base, b"replacement").is_err());
        let mut base = image(b"ramdisk", b"dtb");
        base[2116..2120].copy_from_slice(&2u32.to_le_bytes());
        assert!(VendorBootImage::prepare(&base, b"replacement").is_err());
        let mut base = image(b"ramdisk", b"dtb");
        base.push(1);
        assert!(VendorBootImage::prepare(&base, b"replacement").is_err());
    }
}
