use solana_pay_request::pay::{generate_solana_pay_url, PayRequest};

/// Menguji pembuatan tautan Solana Pay standar menggunakan koin SOL saja
#[test]
fn test_generate_solana_pay_url_sol_only() {
    let req = PayRequest {
        recipient: "4Nd1mBQvC4v38uH8Mtfj28C14S8G8Xp9gU21L5t8s2o".to_string(),
        amount: Some(1.5),
        spl_token: None,
        label: Some("Toko Kopi".to_string()),
        message: Some("Pembelian Espresso".to_string()),
        memo: Some("INV-007".to_string()),
    };

    let result = generate_solana_pay_url(&req);
    assert!(result.is_ok(), "Seharusnya sukses merancang URL");

    let report = result.unwrap();
    // Pastikan parameter dasar tersusun dengan format yang benar
    assert!(report.url.starts_with("solana:4Nd1mBQvC4v38uH8Mtfj28C14S8G8Xp9gU21L5t8s2o?amount=1.5"));
    assert!(report.url.contains("label=Toko%20Kopi"));
    assert!(report.url.contains("message=Pembelian%20Espresso"));
    assert!(report.url.contains("memo=INV-007"));
    
    // Memverifikasi tautan QR Code dari API QR Server terbuat
    assert!(report.qr_code_url.contains("api.qrserver.com"));
    assert!(report.message.contains("Tautan Solana Pay berhasil dibuat!"));
}

/// Menguji pembuatan tautan pembayaran menggunakan token SPL eksternal (seperti USDC)
#[test]
fn test_generate_solana_pay_url_spl() {
    let req = PayRequest {
        recipient: "4Nd1mBQvC4v38uH8Mtfj28C14S8G8Xp9gU21L5t8s2o".to_string(),
        amount: Some(10.0),
        spl_token: Some("EPjFWdd5AufqSSjvk8t7v9yY3dg6fG73Xp1Asut1m1yc".to_string()), // Alamat token USDC asli
        label: None,
        message: None,
        memo: None,
    };

    let result = generate_solana_pay_url(&req);
    assert!(result.is_ok());

    let report = result.unwrap();
    // Pastikan parameter spl-token masuk ke dalam URL
    assert!(report.url.contains("spl-token=EPjFWdd5AufqSSjvk8t7v9yY3dg6fG73Xp1Asut1m1yc"));
}

/// Menguji apakah sistem mendeteksi alamat dompet penerima yang tidak sah/rusak
#[test]
fn test_invalid_recipient() {
    let req = PayRequest {
        recipient: "alamat-salah".to_string(),
        amount: Some(5.0),
        spl_token: None,
        label: None,
        message: None,
        memo: None,
    };

    let result = generate_solana_pay_url(&req);
    assert!(result.is_err(), "Seharusnya mengembalikan error karena alamat tidak valid");
    assert_eq!(result.err().unwrap(), "Alamat dompet penerima (recipient) Solana tidak valid");
}