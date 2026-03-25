use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "admin-ui/dist/"]
pub struct AdminAssets;

pub fn serve_asset(path: &str) -> Option<(Vec<u8>, &'static str)> {
    let file = AdminAssets::get(path).or_else(|| AdminAssets::get("index.html"))?;
    let mime = match path.rsplit('.').next() {
        Some("html") => "text/html",
        Some("js") => "application/javascript",
        Some("css") => "text/css",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    };
    Some((file.data.to_vec(), mime))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serve_index() {
        let result = serve_asset("index.html");
        assert!(result.is_some());
        let (data, mime) = result.unwrap();
        assert_eq!(mime, "text/html");
        assert!(!data.is_empty());
    }

    #[test]
    fn test_serve_unknown_falls_back_to_index() {
        // SPA fallback: unknown paths should return index.html
        let result = serve_asset("nonexistent.xyz");
        assert!(result.is_some());
    }
}
