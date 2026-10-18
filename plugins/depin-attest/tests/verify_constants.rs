#[cfg(test)]
mod tests {
    use bs58;

    #[test]
    fn verify_system_program_id() {
        let system_program_b58 = "11111111111111111111111111111111";
        let decoded = bs58::decode(system_program_b58).into_vec().expect("Failed to decode base58");
        assert_eq!(decoded.len(), 32, "System Program ID should decode to exactly 32 bytes");
        assert!(decoded.iter().all(|&b| b == 0), "System Program ID should be all zeros");
    }

    #[test]
    fn verify_sysvar_recent_blockhashes() {
        let sysvar_b58 = "SysvarRecentB1ockHashes11111111111111111111";
        let decoded = bs58::decode(sysvar_b58).into_vec().expect("Failed to decode base58");
        assert_eq!(decoded.len(), 32, "SysvarRecentB1ockHashes should decode to exactly 32 bytes");
    }
}
