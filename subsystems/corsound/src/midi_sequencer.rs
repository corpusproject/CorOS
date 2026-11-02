//! Standard MIDI 1.0 wire stream & Standard MIDI File (`SMF`) parser (`MidiEvent`,
//! velocity-0 running status `NoteOn -> NoteOff`, 14-bit `PitchBend`, variable-length
//! quantity `decode_vlq`/`encode_vlq`, and tempo `tick_to_microseconds` converter).

use alloc::vec::Vec;

/// Decoded MIDI 1.0 Channel Voice or Tempo Meta event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MidiEvent {
    /// Note Off (`0x8n` or `0x9n` with `velocity == 0`): `(channel, note, velocity)`.
    NoteOff {
        channel: u8,
        note: u8,
        velocity: u8,
    },
    /// Note On (`0x9n` with `velocity > 0`): `(channel, note, velocity)`.
    NoteOn {
        channel: u8,
        note: u8,
        velocity: u8,
    },
    /// Polyphonic Key Pressure / Aftertouch (`0xAn`): `(channel, note, pressure)`.
    PolyKeyPressure {
        channel: u8,
        note: u8,
        pressure: u8,
    },
    /// Control Change (`0xBn`): `(channel, controller, value)`.
    ControlChange {
        channel: u8,
        controller: u8,
        value: u8,
    },
    /// Program Change (`0xCn`): `(channel, program)`.
    ProgramChange {
        channel: u8,
        program: u8,
    },
    /// Channel Pressure / Monophonic Aftertouch (`0xDn`): `(channel, pressure)`.
    ChannelPressure {
        channel: u8,
        pressure: u8,
    },
    /// 14-bit Pitch Bend Wheel (`0xEn`): `value` in `0..=16383` (center `8192`).
    PitchBend {
        channel: u8,
        value: u16,
    },
    /// SMF Tempo Meta Event (`FF 51 03 tt tt tt`): microseconds per quarter note.
    SetTempo {
        microseconds_per_quarter: u32,
    },
    /// SMF End-of-Track Meta Event (`FF 2F 00`).
    EndOfTrack,
}

/// Scheduled SMF track event pairing a MIDI tick delta with a `MidiEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimedMidiEvent {
    /// Delta ticks since the preceding track event.
    pub delta_ticks: u32,
    /// Cumulative absolute ticks from the start of the track.
    pub absolute_ticks: u64,
    /// Decoded event payload.
    pub event: MidiEvent,
}

/// Errors encountered during MIDI stream or SMF track parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MidiError {
    /// Input stream ended before a complete message or VLQ could be read.
    UnexpectedEof,
    /// Variable-length quantity exceeded the 4-byte (28-bit) SMF limit.
    MalformedVlq,
    /// Data byte had bit 7 set (`>= 0x80`) when a 7-bit payload byte was required, or running status was missing.
    InvalidStatusOrDataByte,
}

/// Decode a Standard MIDI File Variable-Length Quantity (VLQ, 1 to 4 bytes, 7 bits per byte),
/// returning `(value, bytes_consumed)`.
pub fn decode_vlq(bytes: &[u8]) -> Result<(u32, usize), MidiError> {
    let mut value = 0u32;
    for (idx, &byte) in bytes.iter().take(4).enumerate() {
        value = (value << 7) | ((byte & 0x7F) as u32);
        if (byte & 0x80) == 0 {
            return Ok((value, idx + 1));
        }
    }
    if bytes.len() < 4 {
        Err(MidiError::UnexpectedEof)
    } else {
        Err(MidiError::MalformedVlq)
    }
}

/// Encode a 28-bit unsigned integer (`<= 0x0FFF_FFFF`) into a Standard MIDI File VLQ buffer (`1..=4` bytes),
/// returning the number of bytes written to `out`.
pub fn encode_vlq(value: u32, out: &mut [u8; 4]) -> usize {
    let clamped = value & 0x0FFF_FFFF;
    if clamped < 0x80 {
        out[0] = clamped as u8;
        1
    } else if clamped < 0x4000 {
        out[0] = (((clamped >> 7) & 0x7F) as u8) | 0x80;
        out[1] = (clamped & 0x7F) as u8;
        2
    } else if clamped < 0x20_0000 {
        out[0] = (((clamped >> 14) & 0x7F) as u8) | 0x80;
        out[1] = (((clamped >> 7) & 0x7F) as u8) | 0x80;
        out[2] = (clamped & 0x7F) as u8;
        3
    } else {
        out[0] = (((clamped >> 21) & 0x7F) as u8) | 0x80;
        out[1] = (((clamped >> 14) & 0x7F) as u8) | 0x80;
        out[2] = (((clamped >> 7) & 0x7F) as u8) | 0x80;
        out[3] = (clamped & 0x7F) as u8;
        4
    }
}

/// Convert MIDI ticks into microseconds given the SMF division (`ticks_per_quarter_note`)
/// and tempo (`microseconds_per_quarter_note`, default `500_000` for 120 BPM).
#[inline]
pub const fn tick_to_microseconds(
    ticks: u64,
    ticks_per_quarter_note: u16,
    microseconds_per_quarter_note: u32,
) -> u64 {
    if ticks_per_quarter_note == 0 {
        return 0;
    }
    (ticks * (microseconds_per_quarter_note as u64)) / (ticks_per_quarter_note as u64)
}

/// Stateful MIDI 1.0 wire & SMF track parser supporting Running Status.
#[derive(Debug, Clone, Default)]
pub struct MidiSequencerParser {
    /// Cached running status byte (`0x80..=0xEF`) for abbreviated channel messages.
    running_status: Option<u8>,
}

impl MidiSequencerParser {
    /// Create a fresh MIDI 1.0 parser with cleared running status.
    pub const fn new() -> Self {
        Self {
            running_status: None,
        }
    }

    /// Parse one MIDI event starting at `bytes`, updating `running_status` and returning `(event, bytes_consumed)`.
    pub fn parse_wire_event(&mut self, bytes: &[u8]) -> Result<(MidiEvent, usize), MidiError> {
        let first = *bytes.first().ok_or(MidiError::UnexpectedEof)?;

        // Check for SMF Meta Event (0xFF).
        if first == 0xFF {
            self.running_status = None;
            if bytes.len() < 2 {
                return Err(MidiError::UnexpectedEof);
            }
            let meta_type = bytes[1];
            let (meta_len, vlq_bytes) = decode_vlq(&bytes[2..])?;
            let payload_start = 2 + vlq_bytes;
            let payload_end = payload_start + (meta_len as usize);
            if payload_end > bytes.len() {
                return Err(MidiError::UnexpectedEof);
            }
            if meta_type == 0x51 && meta_len == 3 {
                let tempo = ((bytes[payload_start] as u32) << 16)
                    | ((bytes[payload_start + 1] as u32) << 8)
                    | (bytes[payload_start + 2] as u32);
                return Ok((
                    MidiEvent::SetTempo {
                        microseconds_per_quarter: tempo,
                    },
                    payload_end,
                ));
            } else if meta_type == 0x2F {
                return Ok((MidiEvent::EndOfTrack, payload_end));
            } else {
                return Err(MidiError::InvalidStatusOrDataByte);
            }
        }

        // Determine status byte (either explicit >= 0x80 or inherited from Running Status).
        let (status, mut cursor) = if (first & 0x80) != 0 {
            if first < 0xF0 {
                self.running_status = Some(first);
            }
            (first, 1usize)
        } else {
            let cached = self
                .running_status
                .ok_or(MidiError::InvalidStatusOrDataByte)?;
            (cached, 0usize)
        };

        let msg_nibble = status & 0xF0;
        let channel = status & 0x0F;

        let read_data_byte = |slice: &[u8], pos: &mut usize| -> Result<u8, MidiError> {
            let b = *slice.get(*pos).ok_or(MidiError::UnexpectedEof)?;
            if (b & 0x80) != 0 {
                return Err(MidiError::InvalidStatusOrDataByte);
            }
            *pos += 1;
            Ok(b)
        };

        let event = match msg_nibble {
            0x80 => {
                let note = read_data_byte(bytes, &mut cursor)?;
                let velocity = read_data_byte(bytes, &mut cursor)?;
                MidiEvent::NoteOff {
                    channel,
                    note,
                    velocity,
                }
            }
            0x90 => {
                let note = read_data_byte(bytes, &mut cursor)?;
                let velocity = read_data_byte(bytes, &mut cursor)?;
                if velocity == 0 {
                    // MIDI 1.0 specification: NoteOn with velocity 0 is semantically a NoteOff
                    // (commonly used to preserve 0x9n Running Status).
                    MidiEvent::NoteOff {
                        channel,
                        note,
                        velocity: 0,
                    }
                } else {
                    MidiEvent::NoteOn {
                        channel,
                        note,
                        velocity,
                    }
                }
            }
            0xA0 => {
                let note = read_data_byte(bytes, &mut cursor)?;
                let pressure = read_data_byte(bytes, &mut cursor)?;
                MidiEvent::PolyKeyPressure {
                    channel,
                    note,
                    pressure,
                }
            }
            0xB0 => {
                let controller = read_data_byte(bytes, &mut cursor)?;
                let value = read_data_byte(bytes, &mut cursor)?;
                MidiEvent::ControlChange {
                    channel,
                    controller,
                    value,
                }
            }
            0xC0 => {
                let program = read_data_byte(bytes, &mut cursor)?;
                MidiEvent::ProgramChange { channel, program }
            }
            0xD0 => {
                let pressure = read_data_byte(bytes, &mut cursor)?;
                MidiEvent::ChannelPressure { channel, pressure }
            }
            0xE0 => {
                let lsb = read_data_byte(bytes, &mut cursor)? as u16;
                let msb = read_data_byte(bytes, &mut cursor)? as u16;
                let value = (msb << 7) | lsb;
                MidiEvent::PitchBend { channel, value }
            }
            _ => return Err(MidiError::InvalidStatusOrDataByte),
        };

        Ok((event, cursor))
    }

    /// Parse a sequence of SMF track events (`[VLQ delta_ticks, MidiEvent, ...]`) from `track_bytes`.
    pub fn parse_smf_track(&mut self, track_bytes: &[u8]) -> Result<Vec<TimedMidiEvent>, MidiError> {
        let mut cursor = 0usize;
        let mut absolute_ticks = 0u64;
        let mut events = Vec::new();

        while cursor < track_bytes.len() {
            let (delta_ticks, vlq_len) = decode_vlq(&track_bytes[cursor..])?;
            cursor += vlq_len;
            absolute_ticks = absolute_ticks.saturating_add(delta_ticks as u64);

            let (event, ev_len) = self.parse_wire_event(&track_bytes[cursor..])?;
            cursor += ev_len;
            events.push(TimedMidiEvent {
                delta_ticks,
                absolute_ticks,
                event,
            });
            if event == MidiEvent::EndOfTrack {
                break;
            }
        }

        Ok(events)
    }
}
