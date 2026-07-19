//! Host-independent RPC boundary. Tests supply a deterministic mock while the
//! WASM shim implements the same trait through host-mediated `wasi:http`.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcAccount {
    pub owner: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationResult {
    pub error: Option<String>,
    pub units_consumed: Option<u64>,
    pub slot: Option<u64>,
}

pub trait RpcClient {
    fn get_account(&mut self, address: &str) -> Result<Option<RpcAccount>, String>;

    fn get_fee_for_message(&mut self, message_base64: &str) -> Result<Option<u64>, String>;

    fn get_minimum_balance_for_rent_exemption(&mut self, data_len: usize) -> Result<u64, String>;

    fn simulate_transaction(
        &mut self,
        transaction_base64: &str,
    ) -> Result<SimulationResult, String>;
}
