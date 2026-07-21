use serde::{Deserialize, Serialize};

// --- STRUKTUR DATA UNTUK RESPONSE SOLANA JSON-RPC ---

#[derive(Deserialize, Debug)]
pub struct RpcResponse {
    pub result: Option<RpcResultValue>,
    pub error: Option<RpcError>,
}

#[derive(Deserialize, Debug)]
pub struct RpcResultValue {
    pub value: Option<AccountValue>,
}

#[derive(Deserialize, Debug)]
pub struct AccountValue {
    pub data: Option<AccountData>,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum AccountData {
    Parsed(ParsedAccountData),
    Raw(String),
}

#[derive(Deserialize, Debug)]
pub struct ParsedAccountData {
    pub parsed: ParsedInfo,
    pub program: String,
}

#[derive(Deserialize, Debug)]
pub struct ParsedInfo {
    pub info: MintInfo,
    #[serde(rename = "type")]
    pub account_type: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MintInfo {
    pub decimals: u8,
    pub mint_authority: Option<String>,
    pub freeze_authority: Option<String>,
    pub supply: String,
    pub is_initialized: bool,
}

#[derive(Deserialize, Debug)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

// --- STRUKTUR HASIL LAPORAN KEAMANAN ---

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SafetyReport {
    pub mint_address: String,
    pub is_safe: bool,
    pub mint_authority_renounced: bool,
    pub freeze_authority_disabled: bool,
    pub supply: String,
    pub decimals: u8,
    pub message: String,
}

// --- FUNGSI LOGIKA UTAMA ---

/// Membuat payload JSON untuk melakukan request getAccountInfo ke Solana RPC
pub fn build_rpc_request(mint_address: &str) -> String {
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            mint_address,
            { "encoding": "jsonParsed" }
        ]
    });
    req.to_string()
}

/// Menganalisis string respon JSON dari RPC untuk menentukan tingkat keamanan token
pub fn parse_rpc_response(mint_address: &str, json_str: &str) -> Result<SafetyReport, String> {
    let resp: RpcResponse = serde_json::from_str(json_str)
        .map_err(|e| format!("Gagal membedah JSON RPC: {e}"))?;

    if let Some(err) = resp.error {
        return Err(format!("Galat RPC ({}): {}", err.code, err.message));
    }

    let result_value = resp.result.ok_or("Tidak ada kolom 'result' pada respon RPC")?;
    let val = result_value.value.ok_or("Alamat token tidak ditemukan di blockchain (Akun tidak aktif)")?;
    
    let account_data = val.data.ok_or("Akun Solana ini tidak memiliki data")?;

    let parsed_data = match account_data {
        AccountData::Parsed(p) => p,
        AccountData::Raw(_) => return Err("Data akun tidak dalam format JSON terurai (apakah ini token SPL standar?)".to_string()),
    };

    // Pastikan ini adalah token SPL (Solana Program Library) standar
    if parsed_data.program != "spl-token" && parsed_data.program != "spl-token-2022" {
        return Err(format!("Pemilik program tidak didukung: {}", parsed_data.program));
    }

    if parsed_data.parsed.account_type != "mint" {
        return Err(format!("Akun ini bukan alamat Mint Token, melainkan: {}", parsed_data.parsed.account_type));
    }

    let mint_info = parsed_data.parsed.info;

    // Memeriksa parameter keamanan utama
    let mint_renounced = mint_info.mint_authority.is_none();
    let freeze_disabled = mint_info.freeze_authority.is_none();
    let is_safe = mint_renounced && freeze_disabled;

    // Menyusun laporan teks ramah manusia untuk Agen AI membaca
    let mut msg = format!("Laporan Keamanan Token ({}):\n\n", mint_address);
    
    if mint_renounced {
        msg.push_str("✅ Otoritas Cetak (Mint Authority) sudah DIMATIKAN (Renounced). Pembuat tidak bisa mencetak suplai token baru secara curang.\n");
    } else {
        msg.push_str("⚠️ Peringatan: Otoritas Cetak (Mint Authority) masih AKTIF! Pembuat token sewaktu-waktu dapat mencetak suplai baru secara tak terbatas (Risiko Inflasi/Rugpull).\n");
    }

    if freeze_disabled {
        msg.push_str("✅ Otoritas Beku (Freeze Authority) sudah NONAKTIF. Pembuat tidak bisa membekukan token di dompet Anda.\n");
    } else {
        msg.push_str("⚠️ Peringatan: Otoritas Beku (Freeze Authority) masih AKTIF! Pembuat token bisa membekukan dompet Anda kapan saja agar tidak bisa dijual kembali (Honeypot/Freeze hazard).\n");
    }

    if is_safe {
        msg.push_str("\n🟢 Status Keamanan: AMAN. Semua indikator risiko dasar telah lolos sensor.");
    } else {
        msg.push_str("\n🔴 Status Keamanan: SANGAT BERBAHAYA! Sangat tidak disarankan untuk melakukan interaksi keuangan dengan token ini.");
    }

    Ok(SafetyReport {
        mint_address: mint_address.to_string(),
        is_safe,
        mint_authority_renounced: mint_renounced,
        freeze_authority_disabled: freeze_disabled,
        supply: mint_info.supply,
        decimals: mint_info.decimals,
        message: msg,
    })
}