use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct SensorReading {
    pub sensor_id: String,
    pub value: f64,
    pub unit: String,
    pub timestamp: i64,
}

pub fn validate_reading(reading: &SensorReading) -> Result<(), String> {
    if reading.sensor_id.trim().is_empty() {
        return Err("sensor_id cannot be empty".to_string());
    }
    if !reading.value.is_finite() {
        return Err("value must be finite".to_string());
    }
    if reading.unit.trim().is_empty() {
        return Err("unit cannot be empty".to_string());
    }
    if reading.timestamp <= 0 {
        return Err("timestamp must be positive".to_string());
    }
    Ok(())
}
