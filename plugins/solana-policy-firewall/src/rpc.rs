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
}

pub trait RpcClient {
    fn get_account(&mut self, address: &str) -> Result<Option<RpcAccount>, String>;

    fn simulate_transaction(
        &mut self,
        transaction_base64: &str,
    ) -> Result<SimulationResult, String>;
}
