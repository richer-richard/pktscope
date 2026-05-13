use std::io::Write;

use crate::decode::DecodedPacket;

pub fn write_json_line(writer: &mut impl Write, pkt: &DecodedPacket) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *writer, pkt)?;
    writer.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::*;

    #[test]
    fn test_json_roundtrip() {
        let pkt = DecodedPacket {
            number: 42,
            timestamp: chrono::Utc::now(),
            wire_len: 100,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            layers: vec![Layer::Payload { offset: 0, len: 4 }],
            summary: PacketSummary {
                source: "10.0.0.1".into(),
                destination: "10.0.0.2".into(),
                protocol: "TCP".into(),
                length: 100,
                info: "test".into(),
                color_hint: ColorHint::Tcp,
            },
            process: None,
            retransmission: false,
        };

        let mut buf = Vec::new();
        write_json_line(&mut buf, &pkt).unwrap();

        let json_str = String::from_utf8(buf).unwrap();
        assert!(json_str.ends_with('\n'));
        let parsed: serde_json::Value = serde_json::from_str(json_str.trim()).unwrap();
        assert_eq!(parsed["number"], 42);
        assert_eq!(parsed["wire_len"], 100);
    }
}
