use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct StakeState {
    pub delegated_lamports: u64,
    pub active_lamports: u64,
    pub activating_lamports: u64,
    pub deactivating_lamports: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct StakeHealth {
    pub active_bps: u16,
    pub status: &'static str,
}

pub fn assess(s: &StakeState) -> StakeHealth {
    let total = s.delegated_lamports.max(1);
    let active = ((s.active_lamports as u128 * 10_000) / total as u128).min(10_000) as u16;
    let status = if s.delegated_lamports == 0 {
        "undelegated"
    } else if s.deactivating_lamports > 0 {
        "deactivating"
    } else if s.activating_lamports > 0 {
        "activating"
    } else {
        "active"
    };
    StakeHealth {
        active_bps: active,
        status,
    }
}

pub fn state_from_rpc(value: &Value) -> Result<StakeState, &'static str> {
    let info = value
        .pointer("/value/data/parsed/info/stake")
        .ok_or("stake account data missing")?;
    let delegated = info
        .pointer("/delegation/stake")
        .and_then(Value::as_u64)
        .ok_or("delegated stake missing")?;
    let active = info
        .get("activeLamports")
        .and_then(Value::as_u64)
        .unwrap_or(delegated);
    Ok(StakeState {
        delegated_lamports: delegated,
        active_lamports: active,
        activating_lamports: info
            .get("activatingLamports")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        deactivating_lamports: info
            .get("deactivatingLamports")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reports_activation() {
        let h = assess(&StakeState {
            delegated_lamports: 100,
            active_lamports: 50,
            activating_lamports: 50,
            deactivating_lamports: 0,
        });
        assert_eq!(h.active_bps, 5000);
        assert_eq!(h.status, "activating");
    }

    #[test]
    fn parses_stake_fixture_conservatively() {
        let value = serde_json::json!({"value":{"data":{"parsed":{"info":{"stake":{
            "delegation":{"stake":1000}, "activeLamports":700, "activatingLamports":300
        }}}}}});
        let state = state_from_rpc(&value).unwrap();
        assert_eq!(state.delegated_lamports, 1000);
        assert_eq!(state.active_lamports, 700);
        assert_eq!(assess(&state).status, "activating");
    }
}
