//! ACPI System Sleep States (S0ix Modern Standby, S3, S4, S5) & Device Power Transition Sequencer.

use alloc::vec::Vec;

/// ACPI Target Sleep State.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SleepState {
    S0ixModernStandby,
    S3SuspendToRam,
    S4Hibernate,
    S5SoftOff,
}

/// Device Power Transition Phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PowerPhase {
    Prepare,
    Suspend,
    SuspendLate,
    SuspendNoirq,
    ResumeNoirq,
    ResumeEarly,
    Resume,
    Complete,
}

/// Device Power Management Callback hook descriptor.
pub struct DevicePowerNode {
    pub name: &'static str,
    pub order: u32,
    pub is_suspended: bool,
}

/// Sleep state machine managing ordered device quiescing and wake sequencing.
pub struct SleepTransitionSequencer {
    pub target_state: SleepState,
    pub devices: Vec<DevicePowerNode>,
    pub current_phase: PowerPhase,
}

impl SleepTransitionSequencer {
    pub fn new(target_state: SleepState) -> Self {
        Self {
            target_state,
            devices: Vec::new(),
            current_phase: PowerPhase::Prepare,
        }
    }

    pub fn register_device(&mut self, name: &'static str, order: u32) {
        self.devices.push(DevicePowerNode {
            name,
            order,
            is_suspended: false,
        });
        self.devices.sort_by_key(|d| d.order);
    }

    /// Progresses through suspension phases, turning off devices in order.
    pub fn execute_suspend_sequence(&mut self) -> bool {
        self.current_phase = PowerPhase::Prepare;
        self.current_phase = PowerPhase::Suspend;
        for dev in &mut self.devices {
            dev.is_suspended = true;
        }
        self.current_phase = PowerPhase::SuspendLate;
        self.current_phase = PowerPhase::SuspendNoirq;
        true
    }

    /// Resumes devices in reverse dependency order.
    pub fn execute_resume_sequence(&mut self) -> bool {
        self.current_phase = PowerPhase::ResumeNoirq;
        self.current_phase = PowerPhase::ResumeEarly;
        self.current_phase = PowerPhase::Resume;
        for dev in self.devices.iter_mut().rev() {
            dev.is_suspended = false;
        }
        self.current_phase = PowerPhase::Complete;
        true
    }
}
