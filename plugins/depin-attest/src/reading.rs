use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct SensorReading {
    pub sensor_id: String,
    pub value_str: String,
    pub unit: String,
    pub timestamp: i64,
}

pub fn validate_reading(reading: &SensorReading) -> Result<(), String> {
    // Defense-in-depth: value_str and timestamp cannot contain the delimiter ('|') by construction, 
    // since they must parse strictly as f64/i64 respectively. sensor_id and unit require explicit 
    // rejection since they're free-form strings, to prevent delimiter-collision signature forgery.
    if reading.sensor_id.trim().is_empty() {
        return Err("sensor_id cannot be empty".to_string());
    }
    if reading.sensor_id.chars().any(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-') {
        return Err("sensor_id can only contain alphanumeric characters, underscores, and hyphens".to_string());
    }
    let parsed_val = reading.value_str.parse::<f64>()
        .map_err(|_| "value_str is not a valid number".to_string())?;
    if !parsed_val.is_finite() {
        return Err("value must be finite".to_string());
    }
    if reading.unit.trim().is_empty() {
        return Err("unit cannot be empty".to_string());
    }
    if reading.unit.contains('|') {
        return Err("unit cannot contain the pipe (|) character".to_string());
    }
    if reading.timestamp <= 0 {
        return Err("timestamp must be positive".to_string());
    }
    Ok(())
}
