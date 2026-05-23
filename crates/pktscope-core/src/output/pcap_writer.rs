use std::io::Write;

use crate::capture::Linktype;

const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;

pub struct PcapWriter<W: Write> {
    writer: W,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut writer: W, linktype: Linktype, snaplen: u32) -> anyhow::Result<Self> {
        // Write global header (24 bytes)
        writer.write_all(&PCAP_MAGIC.to_le_bytes())?;
        writer.write_all(&PCAP_VERSION_MAJOR.to_le_bytes())?;
        writer.write_all(&PCAP_VERSION_MINOR.to_le_bytes())?;
        writer.write_all(&0i32.to_le_bytes())?; // thiszone
        writer.write_all(&0u32.to_le_bytes())?; // sigfigs
        writer.write_all(&snaplen.to_le_bytes())?;
        writer.write_all(&linktype.to_pcap_linktype().to_le_bytes())?;
        writer.flush()?;
        Ok(Self { writer })
    }

    pub fn write_packet(
        &mut self,
        timestamp: chrono::DateTime<chrono::Utc>,
        data: &[u8],
        wire_len: u32,
    ) -> anyhow::Result<()> {
        let ts_secs = timestamp.timestamp() as u32;
        let ts_usecs = timestamp.timestamp_subsec_micros();
        let caplen = data.len() as u32;

        // Packet header (16 bytes)
        self.writer.write_all(&ts_secs.to_le_bytes())?;
        self.writer.write_all(&ts_usecs.to_le_bytes())?;
        self.writer.write_all(&caplen.to_le_bytes())?;
        self.writer.write_all(&wire_len.to_le_bytes())?;
        // Packet data
        self.writer.write_all(data)?;
        Ok(())
    }

    pub fn flush(&mut self) -> anyhow::Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcap_header() {
        let mut buf = Vec::new();
        let _writer = PcapWriter::new(&mut buf, Linktype::Ethernet, 65535).unwrap();
        assert_eq!(buf.len(), 24);
        // Check magic
        assert_eq!(&buf[0..4], &PCAP_MAGIC.to_le_bytes());
        // Check version
        assert_eq!(&buf[4..6], &PCAP_VERSION_MAJOR.to_le_bytes());
        assert_eq!(&buf[6..8], &PCAP_VERSION_MINOR.to_le_bytes());
    }

    #[test]
    fn test_write_packet() {
        let mut buf = Vec::new();
        {
            let mut writer = PcapWriter::new(&mut buf, Linktype::Ethernet, 65535).unwrap();
            let ts = chrono::Utc::now();
            writer.write_packet(ts, &[0xDE, 0xAD], 2).unwrap();
        }
        // 24 (global header) + 16 (packet header) + 2 (data) = 42
        assert_eq!(buf.len(), 42);
    }
}
