use std::io::Write;

use crate::capture::Linktype;

/// Writes the PCAPNG format (Section Header Block + one Interface Description
/// Block, then an Enhanced Packet Block per packet). Little-endian, microsecond
/// timestamp resolution (the PCAPNG default).
pub struct PcapngWriter<W: Write> {
    writer: W,
}

impl<W: Write> PcapngWriter<W> {
    pub fn new(mut writer: W, linktype: Linktype, snaplen: u32) -> anyhow::Result<Self> {
        write_shb(&mut writer)?;
        write_idb(&mut writer, linktype.to_pcap_linktype() as u16, snaplen)?;
        writer.flush()?;
        Ok(Self { writer })
    }

    pub fn write_packet(
        &mut self,
        timestamp: chrono::DateTime<chrono::Utc>,
        data: &[u8],
        wire_len: u32,
    ) -> anyhow::Result<()> {
        let micros = timestamp.timestamp_micros().max(0) as u64;
        let ts_high = (micros >> 32) as u32;
        let ts_low = (micros & 0xFFFF_FFFF) as u32;
        let caplen = data.len() as u32;
        let pad = (4 - (data.len() % 4)) % 4;
        // EPB: 28 fixed bytes + data + padding + 4 (trailing length).
        let total = 32 + data.len() + pad;

        self.writer.write_all(&0x0000_0006u32.to_le_bytes())?; // EPB type
        self.writer.write_all(&(total as u32).to_le_bytes())?;
        self.writer.write_all(&0u32.to_le_bytes())?; // interface id
        self.writer.write_all(&ts_high.to_le_bytes())?;
        self.writer.write_all(&ts_low.to_le_bytes())?;
        self.writer.write_all(&caplen.to_le_bytes())?;
        self.writer.write_all(&wire_len.to_le_bytes())?; // original length
        self.writer.write_all(data)?;
        if pad > 0 {
            self.writer.write_all(&[0u8; 4][..pad])?;
        }
        self.writer.write_all(&(total as u32).to_le_bytes())?;
        Ok(())
    }

    pub fn flush(&mut self) -> anyhow::Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}

fn write_shb<W: Write>(w: &mut W) -> anyhow::Result<()> {
    let total: u32 = 28;
    w.write_all(&0x0A0D_0D0Au32.to_le_bytes())?; // SHB block type
    w.write_all(&total.to_le_bytes())?;
    w.write_all(&0x1A2B_3C4Du32.to_le_bytes())?; // byte-order magic (LE)
    w.write_all(&1u16.to_le_bytes())?; // major version
    w.write_all(&0u16.to_le_bytes())?; // minor version
    w.write_all(&(-1i64).to_le_bytes())?; // section length: unknown
    w.write_all(&total.to_le_bytes())?;
    Ok(())
}

fn write_idb<W: Write>(w: &mut W, linktype: u16, snaplen: u32) -> anyhow::Result<()> {
    let total: u32 = 20;
    w.write_all(&0x0000_0001u32.to_le_bytes())?; // IDB block type
    w.write_all(&total.to_le_bytes())?;
    w.write_all(&linktype.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?; // reserved
    w.write_all(&snaplen.to_le_bytes())?;
    w.write_all(&total.to_le_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_pcapng_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.pcapng");
        {
            let file = std::fs::File::create(&path).unwrap();
            let mut w = PcapngWriter::new(file, Linktype::Ethernet, 65535).unwrap();
            w.write_packet(Utc::now(), &[0xde, 0xad, 0xbe, 0xef, 0x01], 5)
                .unwrap();
            w.write_packet(Utc::now(), &[1, 2, 3, 4], 4).unwrap();
            w.flush().unwrap();
        }
        // The pcap crate reads PCAPNG; verify our output is well-formed.
        let mut cap = pcap::Capture::from_file(&path).unwrap();
        let mut count = 0;
        while cap.next_packet().is_ok() {
            count += 1;
            if count > 10 {
                break;
            }
        }
        assert_eq!(count, 2);
    }
}
