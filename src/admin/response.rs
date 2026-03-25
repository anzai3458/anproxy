use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Error, Response, StatusCode};

pub fn json_ok<T: serde::Serialize>(data: &T) -> Response<BoxBody<Bytes, Error>> {
    let body = serde_json::json!({ "ok": true, "data": data });
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())).map_err(|e| match e {}).boxed())
        .unwrap()
}

pub fn json_err(status: StatusCode, msg: &str) -> Response<BoxBody<Bytes, Error>> {
    let body = serde_json::json!({ "ok": false, "error": msg });
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())).map_err(|e| match e {}).boxed())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_ok_response() {
        let resp = json_ok(&serde_json::json!({"key": "value"}));
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_json_err_response() {
        let resp = json_err(StatusCode::BAD_REQUEST, "bad input");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
