pub mod json;
pub mod pcap_writer;
pub mod pcapng_writer;

use std::io::Write;

/// A sink for captured packets, implemented by the classic-pcap and PCAPNG
/// writers so the capture frontend can target either format behind one type.
pub trait PacketSink {
    fn write_packet(
        &mut self,
        timestamp: chrono::DateTime<chrono::Utc>,
        data: &[u8],
        wire_len: u32,
    ) -> anyhow::Result<()>;
    fn flush(&mut self) -> anyhow::Result<()>;
}

impl<W: Write> PacketSink for pcap_writer::PcapWriter<W> {
    fn write_packet(
        &mut self,
        timestamp: chrono::DateTime<chrono::Utc>,
        data: &[u8],
        wire_len: u32,
    ) -> anyhow::Result<()> {
        pcap_writer::PcapWriter::write_packet(self, timestamp, data, wire_len)
    }
    fn flush(&mut self) -> anyhow::Result<()> {
        pcap_writer::PcapWriter::flush(self)
    }
}

impl<W: Write> PacketSink for pcapng_writer::PcapngWriter<W> {
    fn write_packet(
        &mut self,
        timestamp: chrono::DateTime<chrono::Utc>,
        data: &[u8],
        wire_len: u32,
    ) -> anyhow::Result<()> {
        pcapng_writer::PcapngWriter::write_packet(self, timestamp, data, wire_len)
    }
    fn flush(&mut self) -> anyhow::Result<()> {
        pcapng_writer::PcapngWriter::flush(self)
    }
}
