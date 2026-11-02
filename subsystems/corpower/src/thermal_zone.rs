//! Thermal Zones, ACPI Trip Points & Proportional-Integral-Derivative (PID) Fan Controller.

use alloc::vec::Vec;

/// Thermal Trip Point Type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TripPointType {
    Active,
    Passive,
    Hot,
    Critical,
}

/// Thermal Trip Point definition in milliCelsius.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TripPoint {
    pub trip_type: TripPointType,
    pub temp_millicelsius: i32,
    pub cooling_device_id: u32,
}

/// Discrete PID Fan Controller for proactive thermal management.
pub struct PidFanGovernor {
    pub target_temp_mc: i32,
    pub kp: i32,
    pub ki: i32,
    pub kd: i32,
    pub integral_error: i32,
    pub last_error: i32,
    pub current_duty_percent: u8,
}

impl PidFanGovernor {
    pub fn new(target_temp_mc: i32, kp: i32, ki: i32, kd: i32) -> Self {
        Self {
            target_temp_mc,
            kp,
            ki,
            kd,
            integral_error: 0,
            last_error: 0,
            current_duty_percent: 20,
        }
    }

    /// Evaluates current temperature and computes PWM fan duty cycle (0..100%).
    pub fn update(&mut self, current_temp_mc: i32) -> u8 {
        let error = current_temp_mc - self.target_temp_mc;
        self.integral_error = (self.integral_error + error).clamp(-100_000, 100_000);
        let derivative = error - self.last_error;
        self.last_error = error;

        let output = (self.kp * error + self.ki * self.integral_error + self.kd * derivative) / 1000;
        let duty = (20 + output).clamp(0, 100) as u8;
        self.current_duty_percent = duty;
        duty
    }
}

/// Thermal Zone coordinating sensor readings and trip points.
pub struct ThermalZone {
    pub id: u32,
    pub current_temp_mc: i32,
    pub trip_points: Vec<TripPoint>,
    pub pid: PidFanGovernor,
}

impl ThermalZone {
    pub fn new(id: u32, target_temp_mc: i32) -> Self {
        Self {
            id,
            current_temp_mc: 25_000,
            trip_points: Vec::new(),
            pid: PidFanGovernor::new(target_temp_mc, 10, 1, 5),
        }
    }

    pub fn set_temperature(&mut self, temp_mc: i32) -> Option<TripPointType> {
        self.current_temp_mc = temp_mc;
        self.pid.update(temp_mc);

        for trip in &self.trip_points {
            if temp_mc >= trip.temp_millicelsius {
                if trip.trip_type == TripPointType::Critical {
                    return Some(TripPointType::Critical);
                }
            }
        }
        None
    }
}
