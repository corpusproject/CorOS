#![no_std]
//! `corsound` — CorOS Kernel Audio, Polyphonic Mixer & DSP Subsystem.
//!
//! Provides an ALSA/PipeWire-grade audio stack in pure `#![no_std]` Rust:
//! 1. [`pcm_ringbuf`]: Circular PCM ring buffer with `hw_ptr`/`appl_ptr` boundary wrapping, `XRUN` recovery, and sample format converters.
//! 2. [`multi_mixer`]: 16-channel polyphonic software mixer with Q8.8 gain, constant-power stereo panpot law, solo/mute groups, and soft-clipping saturator.
//! 3. [`wav_codec`]: RIFF/WAVE container parser/encoder for Linear PCM (`FMT_PCM = 1`) and IEEE Float (`FMT_IEEE_FLOAT = 3`).
//! 4. [`flac_frame`]: Lossless FLAC frame header parser, UTF-8 coded number decoder, CRC-8 (`0x07`) verifier, and Fixed LPC (`0..=4`) subframe decoder.
//! 5. [`fm_synth`]: 4-Operator FM phase-accumulator synthesizer with ADSR envelopes, quarter-wave sine LUT, and 4 DX algorithms.
//! 6. [`biquad_dsp`]: Fixed-point Q16.16 Direct-Form I Biquad IIR filters and 5-band Master Parametric Equalizer cascade.
//! 7. [`midi_sequencer`]: Standard MIDI 1.0 wire stream & SMF track parser with velocity-0 running status, VLQ codec, and tick-to-microsecond tempo conversion.
//! 8. [`hda_patch`]: Intel HD Audio codec pin-complex topology router, `DefaultPinConfig` decoder, EAPD control, and headphone jack-sense auto-mute state machine.
//! 9. [`spatial_hrtf`]: 3D binaural positional processor with Woodworth-Schlosberg ITD fractional delay lines, ILD head-shadowing, and inverse-square distance attenuation.
//! 10. [`audio_loopback`]: Full-duplex virtual loopback bridge (`AloopSubstream`) with fractional clock-drift compensation and automatic silence injection.

extern crate alloc;

pub mod audio_loopback;
pub mod biquad_dsp;
pub mod flac_frame;
pub mod fm_synth;
pub mod hda_patch;
pub mod midi_sequencer;
pub mod multi_mixer;
pub mod pcm_ringbuf;
pub mod spatial_hrtf;
pub mod wav_codec;

use alloc::vec::Vec;

use audio_loopback::AudioLoopbackBridge;
use biquad_dsp::{BiquadCoeffs, BiquadState, MasterParametricEq};
use flac_frame::{
    compute_flac_crc8, decode_constant_subframe, decode_fixed_lpc_subframe,
    decode_verbatim_subframe, FlacChannelAssignment, FlacFrameHeader,
};
use fm_synth::{DxAlgorithm, FmSynthVoice};
use hda_patch::{
    AutoMuteOutputRoute, DefaultDeviceRole, DefaultPinConfig, HdaPinComplexRouter, JackColor,
    PinWidgetCap, PortConnectivity,
};
use midi_sequencer::{
    decode_vlq, encode_vlq, tick_to_microseconds, MidiEvent, MidiSequencerParser,
};
use multi_mixer::{constant_power_pan_gains, PolyphonicMixer, MAX_MIXER_CHANNELS};
use pcm_ringbuf::{
    convert_raw_to_s16_vec, convert_raw_to_s32_vec, PcmError, PcmRingBuffer, PcmSampleFormat,
    PcmStreamState,
};
use spatial_hrtf::SpatialHrtfProcessor;
use wav_codec::{WavFormatChunk, WavHeader, FMT_IEEE_FLOAT, FMT_PCM};

/// Execute comprehensive self-tests across all 10 `corsound` audio & DSP modules.
/// Returns the number of modules that passed verification (`10` when all pass).
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;

    // 1. Verify ALSA PCM Ring Buffer, boundary wrap, XRUN detection/recovery & format conversion.
    if test_pcm_ringbuf() {
        passed += 1;
    }

    // 2. Verify 16-channel polyphonic mixer, constant-power pan law, solo/mute & soft clipper.
    if test_multi_mixer() {
        passed += 1;
    }

    // 3. Verify RIFF/WAVE header builder, parser, frame slicer & IEEE float converter.
    if test_wav_codec() {
        passed += 1;
    }

    // 4. Verify FLAC frame header parser, UTF-8 coded number, CRC-8 & Fixed LPC orders 0..=4.
    if test_flac_frame() {
        passed += 1;
    }

    // 5. Verify 4-Operator FM Synthesizer, ADSR envelope, sine LUT & DX algorithms.
    if test_fm_synth() {
        passed += 1;
    }

    // 6. Verify Q16.16 Biquad IIR filter topologies & 5-band Master Parametric EQ cascade.
    if test_biquad_dsp() {
        passed += 1;
    }

    // 7. Verify MIDI 1.0 wire stream & SMF parser, running status velocity-0, VLQ & tempo.
    if test_midi_sequencer() {
        passed += 1;
    }

    // 8. Verify HD Audio pin-complex topology router, config default decoder & auto-mute state machine.
    if test_hda_patch() {
        passed += 1;
    }

    // 9. Verify 3D Spatial HRTF ITD fractional delay, ILD head shadow & inverse-square distance attenuation.
    if test_spatial_hrtf() {
        passed += 1;
    }

    // 10. Verify virtual audio loopback full-duplex bridge, clock drift compensator & silence injector.
    if test_audio_loopback() {
        passed += 1;
    }

    passed
}

fn test_pcm_ringbuf() -> bool {
    let mut ring = match PcmRingBuffer::new(2, 4, 2) {
        Ok(r) => r,
        Err(_) => return false,
    };
    ring.set_pointers_for_wrap_test(2);
    let stereo_frames: [i16; 8] = [1000, -1000, 2000, -2000, 3000, -3000, 4000, -4000];
    let written = ring.write_interleaved(&stereo_frames).unwrap_or(0);
    if written != 4 || ring.state() != PcmStreamState::Running {
        return false;
    }

    let mut dma_out = [0i16; 8];
    if ring.consume_hardware_period(&mut dma_out).is_err() || dma_out != stereo_frames {
        return false;
    }

    // Trigger underrun (XRUN) by consuming when empty, then recover.
    let xrun_res = ring.consume_hardware_period(&mut dma_out);
    if xrun_res != Err(PcmError::XrunDetected) || ring.state() != PcmStreamState::Xrun {
        return false;
    }
    if ring.recover_from_xrun().is_err() || ring.state() != PcmStreamState::Prepared {
        return false;
    }

    let mut raw_s24 = [0u8; 3];
    PcmSampleFormat::S24Le.encode_from_s32(0x4000_0000, &mut raw_s24);
    let s16_vec = convert_raw_to_s16_vec(PcmSampleFormat::S24Le, &raw_s24);
    let s32_vec = convert_raw_to_s32_vec(PcmSampleFormat::U8, &[255u8]);
    !s16_vec.is_empty() && s16_vec[0] > 16_000 && !s32_vec.is_empty() && s32_vec[0] > 0
}

fn test_multi_mixer() -> bool {
    let (center_l, center_r) = constant_power_pan_gains(0);
    if center_l != center_r || center_l < 23_000 {
        return false;
    }
    let mut mixer = PolyphonicMixer::new();
    mixer.channels[0].gain_q8_8 = 512; // 2.0x boost
    mixer.channels[0].pan = -64; // Hard left
    mixer.channels[0].solo = true;
    mixer.channels[1].gain_q8_8 = 256;
    mixer.channels[1].pan = 64; // Muted because channel 0 is soloed

    let mut frame_in = [0i16; MAX_MIXER_CHANNELS];
    frame_in[0] = 20_000;
    frame_in[1] = 20_000;
    let (out_l, out_r) = mixer.mix_frame(&frame_in);
    out_l > 24_576 && out_r == 0 && mixer.meter.soft_clip_events > 0
}

fn test_wav_codec() -> bool {
    let fmt = WavFormatChunk::new(FMT_PCM, 2, 48_000, 16);
    let hdr = WavHeader {
        format: fmt,
        data_offset: 44,
        data_size: 16,
    };
    let raw_hdr = hdr.build_riff_header();
    let mut container = Vec::with_capacity(60);
    container.extend_from_slice(&raw_hdr);
    container.extend_from_slice(&[1u8; 16]);

    let parsed = match WavHeader::parse(&container) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sliced = parsed.slice_sample_frames(&container, 1, 2).unwrap_or(&[]);
    let float_sample = WavHeader::ieee_float32_le_to_s16(0.5f32.to_le_bytes());
    parsed.total_frames() == 4
        && sliced.len() == 8
        && float_sample > 16_300
        && FMT_IEEE_FLOAT == 3
}

fn test_flac_frame() -> bool {
    // Build a valid FLAC frame header: sync 0x3FFE (fixed blocksize = 0),
    // block_size code 8 (256 samples), sample_rate code 10 (48000 Hz),
    // 2 independent channels (code 1), 16-bit (code 4), frame 0 (0x00), plus CRC-8.
    let mut hdr_bytes = [0xFF, 0xF8, 0x8A, 0x18, 0x00, 0x00];
    hdr_bytes[5] = compute_flac_crc8(&hdr_bytes[..5]);

    let parsed = match FlacFrameHeader::parse(&hdr_bytes) {
        Ok(h) => h,
        Err(_) => return false,
    };
    if parsed.block_size != 256
        || parsed.sample_rate != 48_000
        || parsed.channel_assignment != FlacChannelAssignment::Independent(2)
        || parsed.bits_per_sample != 16
    {
        return false;
    }

    let const_sub = decode_constant_subframe(42, 4);
    let verb_sub = decode_verbatim_subframe(&[10, 20, 30]);
    let lpc_order_two = match decode_fixed_lpc_subframe(2, &[100, 200], &[0, 0, 5]) {
        Ok(v) => v,
        Err(_) => return false,
    };
    // Order 2 with 0 residual extrapolates linear ramp: 100, 200, 300, 400, then 500 + 5 = 505.
    const_sub.len() == 4 && verb_sub.len() == 3 && lpc_order_two == [100, 200, 300, 400, 505]
}

fn test_fm_synth() -> bool {
    let mut voice = FmSynthVoice::new(48_000, DxAlgorithm::SerialCascade);
    voice.note_on(69); // A4 = 440 Hz
    let mut energy = 0i64;
    for _ in 0..64 {
        let s = voice.render_sample() as i64;
        energy += s.abs();
    }
    voice.algorithm = DxAlgorithm::ParallelPairs;
    for _ in 0..32 {
        let s = voice.render_sample() as i64;
        energy += s.abs();
    }
    voice.note_off();
    energy > 1_000
}

fn test_biquad_dsp() -> bool {
    let lp_coeffs = BiquadCoeffs::low_pass(1_000, 48_000, 181);
    let hp_coeffs = BiquadCoeffs::high_pass(1_000, 48_000, 181);
    let bp_coeffs = BiquadCoeffs::band_pass(1_000, 48_000, 181);
    let notch_coeffs = BiquadCoeffs::notch(1_000, 48_000, 181);
    let mut lp_filter = BiquadState::new(lp_coeffs);
    let mut eq = MasterParametricEq::new(48_000);
    eq.set_band_coeffs(0, BiquadCoeffs::peaking_eq(80, 48_000, 181, 320));

    let mut step_response = 0i16;
    let mut eq_out = 0i16;
    for _ in 0..32 {
        step_response = lp_filter.process_sample(10_000);
        eq_out = eq.process_sample(step_response);
    }
    step_response > 0
        && eq_out != 0
        && hp_coeffs.b_zero > 0
        && bp_coeffs.b_zero > 0
        && notch_coeffs.b_zero > 0
}

fn test_midi_sequencer() -> bool {
    let mut vlq_buf = [0u8; 4];
    let n = encode_vlq(0x0001_2345, &mut vlq_buf);
    let (decoded_val, consumed) = match decode_vlq(&vlq_buf[..n]) {
        Ok(res) => res,
        Err(_) => return false,
    };
    if decoded_val != 0x0001_2345 || consumed != n {
        return false;
    }

    // SMF track stream testing NoteOn, running status velocity-0 NoteOff, PitchBend, Tempo, and EndOfTrack.
    let smf_track: [u8; 19] = [
        0x00, 0x90, 60, 100, // delta 0: NoteOn ch 0, note 60, vel 100
        0x78, 60, 0, // delta 120: Running status 0x90 with vel 0 -> NoteOff
        0x00, 0xE0, 0x00, 0x40, // delta 0: PitchBend center (8192)
        0x00, 0xFF, 0x51, 0x03, 0x07, 0xA1, 0x20, // delta 0: SetTempo 500_000 us/qn (120 BPM)
        0x00, // trailing check stopped by EndOfTrack if present; let's parse first 4 events
    ];
    let mut parser = MidiSequencerParser::new();
    let events = match parser.parse_smf_track(&smf_track[..18]) {
        Ok(evs) => evs,
        Err(_) => return false,
    };
    let usec = tick_to_microseconds(480, 480, 500_000);
    events.len() == 4
        && matches!(events[0].event, MidiEvent::NoteOn { note: 60, .. })
        && matches!(events[1].event, MidiEvent::NoteOff { note: 60, .. })
        && matches!(events[2].event, MidiEvent::PitchBend { value: 8192, .. })
        && usec == 500_000
}

fn test_hda_patch() -> bool {
    // Config default: Jack (0b00), Front panel (0x02), HpOut (0x2), Green (0x4), Assoc 1, Seq 0xF
    let raw_cfg: u32 = (0b00 << 30) | (0x02 << 24) | (0x2 << 20) | (0x4 << 12) | 0x1F;
    let cfg = DefaultPinConfig(raw_cfg);
    if cfg.connectivity() != PortConnectivity::Jack
        || cfg.default_device() != DefaultDeviceRole::HpOut
        || cfg.color() != JackColor::Green
    {
        return false;
    }

    let spk_cap = PinWidgetCap((1 << 4) | (1 << 16)); // Output + EAPD
    let hp_cap = PinWidgetCap((1 << 2) | (1 << 3) | (1 << 4)); // Presence + HP Drive + Output
    let mut router = HdaPinComplexRouter::new(0, 0x14, spk_cap, 0x21, hp_cap);

    let verbs_plugged = router.update_jack_sense(1 << 31);
    let plugged_ok = router.route == AutoMuteOutputRoute::HeadphonesActiveSpeakersMuted
        && router.speaker_eapd == 0
        && verbs_plugged[0] != 0;

    let _verbs_unplugged = router.update_jack_sense(0);
    let unplugged_ok =
        router.route == AutoMuteOutputRoute::InternalSpeakersActive && router.speaker_eapd != 0;

    plugged_ok && unplugged_ok
}

fn test_spatial_hrtf() -> bool {
    let mut spatial = SpatialHrtfProcessor::new(48_000, 60, 100, 100);
    let mut left_energy = 0i64;
    let mut right_energy = 0i64;
    for idx in 0..48 {
        let pulse = if idx < 16 { 16_000i16 } else { 0i16 };
        let (l, r) = spatial.process_mono_frame(pulse);
        left_energy += (l as i64).abs();
        right_energy += (r as i64).abs();
    }
    // Source at +60 deg (right side) means right ear has higher amplitude than shadowed left ear.
    right_energy > left_energy && left_energy > 0
}

fn test_audio_loopback() -> bool {
    let mut bridge = AudioLoopbackBridge::new(0, 0, 48_000, 2, 64);
    bridge.set_consumer_active(true);

    // 1. Pull while producer is inactive -> must inject zero-fill silence frames.
    let mut cap_buf = [999i16; 8];
    bridge.pull_capture_frames(&mut cap_buf);
    if bridge.silence_frames_injected != 4 || cap_buf.iter().any(|&s| s != 0) {
        return false;
    }

    // 2. Activate producer, configure +500 ppm clock drift, push audio, and pull resampled frames.
    bridge.set_producer_active(true);
    bridge.set_clock_drift_ppm(500);
    let play_buf: [i16; 16] = [
        1000, -1000, 2000, -2000, 3000, -3000, 4000, -4000, 5000, -5000, 6000, -6000, 7000, -7000,
        8000, -8000,
    ];
    let pushed = bridge.push_playback_frames(&play_buf);
    bridge.pull_capture_frames(&mut cap_buf);
    pushed == 8 && cap_buf.iter().any(|&s| s != 0)
}
