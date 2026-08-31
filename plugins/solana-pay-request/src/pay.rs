use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PayRequest {
    pub recipient: String,
    pub amount: Option<f64>,
    pub spl_token: Option<String>,
    pub label: Option<String>,
    pub message: Option<String>,
    pub memo: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PayResponse {
    pub url: String,
    pub qr_code_url: String,
    pub message: String,
}

/// Menghasilkan URL standar Solana Pay dan QR Code gambar instan
pub fn generate_solana_pay_url(req: &PayRequest) -> Result<PayResponse, String> {
    // Validasi panjang alamat penerima (panjang alamat publik Solana adalah 32-44 karakter Base58)
    if req.recipient.len() < 32 || req.recipient.len() > 44 {
        return Err("Alamat dompet penerima (recipient) Solana tidak valid".to_string());
    }

    let mut url = format!("solana:{}", req.recipient);
    let mut query_params = Vec::new();

    if let Some(amount) = req.amount {
        if amount <= 0.0 {
            return Err("Jumlah pembayaran (amount) harus lebih besar dari 0".to_string());
        }
        query_params.push(format!("amount={}", amount));
    }

    if let Some(ref token) = req.spl_token {
        if token.len() < 32 || token.len() > 44 {
            return Err("Alamat kontrak SPL token tidak valid".to_string());
        }
        query_params.push(format!("spl-token={}", token));
    }

    if let Some(ref label) = req.label {
        let encoded = urlencoding::encode(label);
        query_params.push(format!("label={}", encoded));
    }

    if let Some(ref message) = req.message {
        let encoded = urlencoding::encode(message);
        query_params.push(format!("message={}", encoded));
    }

    if let Some(ref memo) = req.memo {
        let encoded = urlencoding::encode(memo);
        query_params.push(format!("memo={}", encoded));
    }

    if !query_params.is_empty() {
        url.push_str("?");
        url.push_str(&query_params.join("&"));
    }

    // Menghasilkan tautan QR Code gambar yang indah menggunakan API publik terbuka yang andal
    let encoded_url = urlencoding::encode(&url);
    let qr_code_url = format!(
        "https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={}",
        encoded_url
    );

    let mut user_msg = format!("Tautan Solana Pay berhasil dibuat!\n\n🔗 Tautan Pembayaran: {}\n", url);
    user_msg.push_str(&format!("📸 Pindai QR Code di bawah untuk membayar:\n{}\n\n", qr_code_url));
    user_msg.push_str("*(Agen AI dapat merender gambar ini langsung dalam format Markdown obrolan!)*");

    Ok(PayResponse {
        url,
        qr_code_url,
        message: user_msg,
    })
}