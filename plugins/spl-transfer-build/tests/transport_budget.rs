use spl_transfer_build::rpc::{collect_http_response, TransportError};

fn chunks(parts: &[&[u8]]) -> Vec<Result<Vec<u8>, TransportError>> {
    parts.iter().map(|part| Ok(part.to_vec())).collect()
}

#[test]
fn http_200_within_limit_succeeds() {
    assert_eq!(
        collect_http_response(200, chunks(&[b"{\"ok\":", b"true}"]), 32),
        Ok("{\"ok\":true}".to_string())
    );
}

#[test]
fn redirects_and_error_statuses_are_refused_without_exposing_content() {
    let secret_url = "https://rpc.example.invalid/keyed-secret";
    let secret_body = b"upstream response body must stay private".as_slice();
    for status in [302, 400, 500] {
        let error =
            collect_http_response(status, chunks(&[secret_body]), 128).expect_err("non-200 status");
        assert_eq!(error, TransportError::HttpStatus(status));
        let displayed = error.to_string();
        assert!(!displayed.contains(secret_url));
        assert!(!displayed.contains("upstream response body"));
    }
}

#[test]
fn aggregate_response_size_boundary_is_enforced() {
    assert_eq!(
        collect_http_response(200, chunks(&[b"1234", b"5678"]), 8),
        Ok("12345678".to_string()),
        "the documented boundary is inclusive"
    );
    assert_eq!(
        collect_http_response(200, chunks(&[b"123456789"]), 8),
        Err(TransportError::ResponseTooLarge)
    );
    assert_eq!(
        collect_http_response(200, chunks(&[b"12", b"34", b"56", b"789"]), 8),
        Err(TransportError::ResponseTooLarge),
        "individually small chunks must share one aggregate budget"
    );
}

#[test]
fn size_errors_do_not_echo_the_rpc_url_or_body() {
    let secret_url = "https://rpc.example.invalid/api-key";
    let secret_body = b"private node diagnostic".as_slice();
    let error =
        collect_http_response(200, chunks(&[secret_body]), 4).expect_err("oversized response");
    let displayed = error.to_string();
    assert!(!displayed.contains(secret_url));
    assert!(!displayed.contains("private node diagnostic"));
}
