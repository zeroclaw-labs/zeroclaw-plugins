use depin_attest::reading::{validate_reading, SensorReading};

#[test]
fn test_valid_reading() {
    let r = SensorReading {
        sensor_id: "SENS-01".to_string(),
        value: 23.5,
        unit: "Celsius".to_string(),
        timestamp: 1670000000,
    };
    assert!(validate_reading(&r).is_ok());
}

#[test]
fn test_empty_sensor_id() {
    let r = SensorReading {
        sensor_id: "   ".to_string(),
        value: 23.5,
        unit: "Celsius".to_string(),
        timestamp: 1670000000,
    };
    assert!(validate_reading(&r).is_err());
}

#[test]
fn test_non_finite_value() {
    let r = SensorReading {
        sensor_id: "SENS-01".to_string(),
        value: f64::NAN,
        unit: "Celsius".to_string(),
        timestamp: 1670000000,
    };
    assert!(validate_reading(&r).is_err());
}

#[test]
fn test_empty_unit() {
    let r = SensorReading {
        sensor_id: "SENS-01".to_string(),
        value: 23.5,
        unit: "".to_string(),
        timestamp: 1670000000,
    };
    assert!(validate_reading(&r).is_err());
}

#[test]
fn test_non_positive_timestamp() {
    let r = SensorReading {
        sensor_id: "SENS-01".to_string(),
        value: 23.5,
        unit: "Celsius".to_string(),
        timestamp: 0,
    };
    assert!(validate_reading(&r).is_err());
    
    let r2 = SensorReading {
        sensor_id: "SENS-01".to_string(),
        value: 23.5,
        unit: "Celsius".to_string(),
        timestamp: -50,
    };
    assert!(validate_reading(&r2).is_err());
}
