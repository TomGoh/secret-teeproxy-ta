//! Credential-bound HTTPS destination and provider-specific API framing.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::{Host, Url};

use crate::relay::Operation;

pub const CUSTOM_PROFILE_ID: &str = "custom-provider-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderType {
    OpenaiCompatible,
    OpenaiResponses,
    AnthropicMessages,
    GoogleGemini,
    OllamaNative,
}

impl ProviderType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenaiCompatible => "openai_compatible",
            Self::OpenaiResponses => "openai_responses",
            Self::AnthropicMessages => "anthropic_messages",
            Self::GoogleGemini => "google_gemini",
            Self::OllamaNative => "ollama_native",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderConfig {
    provider_type: ProviderType,
    base_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderProfile {
    config: Option<ProviderConfig>,
    host: String,
    port: u16,
    authority: String,
    base_path: String,
}

impl ProviderProfile {
    pub fn deepseek() -> Self {
        Self {
            config: None,
            host: "api.deepseek.com".to_owned(),
            port: 443,
            authority: "api.deepseek.com".to_owned(),
            base_path: "/".to_owned(),
        }
    }

    pub fn from_metadata(profile_id: &str, config: Option<&Value>) -> Result<Self, &'static str> {
        if profile_id == crate::store::PROFILE_ID {
            return match config {
                None => Ok(Self::deepseek()),
                Some(_) => Err("built-in profile configuration is fixed"),
            };
        }
        if profile_id != CUSTOM_PROFILE_ID {
            return Err("unsupported provider profile");
        }
        let mut config: ProviderConfig =
            serde_json::from_value(config.cloned().ok_or("missing provider configuration")?)
                .map_err(|_| "invalid provider configuration")?;
        if config.base_url.is_empty()
            || config.base_url.len() > 1024
            || config
                .base_url
                .bytes()
                .any(|byte| byte <= 32 || byte == 127)
            || config.base_url.contains('\\')
        {
            return Err("invalid provider URL");
        }
        let mut url = Url::parse(&config.base_url).map_err(|_| "invalid provider URL")?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.port() == Some(0)
        {
            return Err("provider URL requires an HTTPS origin and path");
        }
        let host = url.host().ok_or("missing provider host")?;
        let (hostname, authority_host) = match host {
            Host::Domain(name) => (name.to_owned(), name.to_owned()),
            Host::Ipv4(address) => (address.to_string(), address.to_string()),
            Host::Ipv6(address) => (address.to_string(), format!("[{address}]")),
        };
        let port = url.port_or_known_default().ok_or("missing provider port")?;
        let mut base_path = url.path().to_owned();
        if !base_path.ends_with('/') {
            base_path.push('/');
            url.set_path(&base_path);
        }
        let authority = if port == 443 {
            authority_host
        } else {
            format!("{authority_host}:{port}")
        };
        config.base_url = url.to_string();
        if config.base_url.len() > 1024 {
            return Err("normalized provider URL exceeds limit");
        }
        Ok(Self {
            config: Some(config),
            host: hostname,
            port,
            authority,
            base_path,
        })
    }

    pub fn config(&self) -> Option<Value> {
        self.config.as_ref().map(|config| json!(config))
    }

    pub fn provider_type(&self) -> Option<ProviderType> {
        self.config.as_ref().map(|config| config.provider_type)
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn connect_target(&self) -> Value {
        json!({"host":self.host,"port":self.port,"sni":self.host,"alpn":"http/1.1"})
    }

    pub fn supports(&self, operation: Operation) -> bool {
        if operation == Operation::Models {
            return true;
        }
        match self.provider_type() {
            None => matches!(
                operation,
                Operation::Chat | Operation::Responses | Operation::Messages
            ),
            Some(ProviderType::OpenaiCompatible) => operation == Operation::Chat,
            Some(ProviderType::OpenaiResponses) => operation == Operation::Responses,
            Some(ProviderType::AnthropicMessages) => operation == Operation::Messages,
            Some(ProviderType::GoogleGemini) => operation == Operation::Generate,
            Some(ProviderType::OllamaNative) => operation == Operation::OllamaChat,
        }
    }

    pub fn auth_header(&self, operation: Operation) -> &'static str {
        match (self.provider_type(), operation) {
            (Some(ProviderType::GoogleGemini), _) => "x-goog-api-key",
            (Some(ProviderType::AnthropicMessages), _) | (None, Operation::Messages) => "x-api-key",
            _ => "Authorization",
        }
    }

    pub fn anthropic_version(&self) -> Option<&'static str> {
        (self.provider_type() == Some(ProviderType::AnthropicMessages)).then_some("2023-06-01")
    }

    pub fn request_target(
        &self,
        operation: Operation,
        model_id: Option<&str>,
        stream: bool,
    ) -> Result<String, &'static str> {
        if !self.supports(operation) {
            return Err("provider operation mismatch");
        }
        if operation != Operation::Generate && model_id.is_some() {
            return Err("model path is only valid for Gemini");
        }
        let suffix = match operation {
            Operation::Chat => "chat/completions".to_owned(),
            Operation::Responses => "responses".to_owned(),
            Operation::Messages if self.config.is_none() => "anthropic/v1/messages".to_owned(),
            Operation::Messages => "messages".to_owned(),
            Operation::Models if self.provider_type() == Some(ProviderType::OllamaNative) => {
                "tags".to_owned()
            }
            Operation::Models => "models".to_owned(),
            Operation::OllamaChat => "chat".to_owned(),
            Operation::Generate => {
                let model = model_id.ok_or("missing Gemini model ID")?;
                let model = model.strip_prefix("models/").unwrap_or(model);
                if model.is_empty()
                    || model.len() > 256
                    || model.bytes().any(|byte| byte <= 32 || byte == 127)
                {
                    return Err("invalid Gemini model ID");
                }
                let method = if stream {
                    "streamGenerateContent?alt=sse"
                } else {
                    "generateContent"
                };
                format!("models/{}:{method}", encode_segment(model))
            }
        };
        Ok(format!("{}{suffix}", self.base_path))
    }
}

fn encode_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 15) as usize] as char);
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custom(provider_type: &str, base_url: &str) -> ProviderProfile {
        ProviderProfile::from_metadata(
            CUSTOM_PROFILE_ID,
            Some(&json!({"provider_type":provider_type,"base_url":base_url})),
        )
        .unwrap()
    }

    #[test]
    fn exact_paths_and_authentication_for_all_provider_types() {
        let deepseek = ProviderProfile::deepseek();
        for (operation, path, auth) in [
            (Operation::Chat, "/chat/completions", "Authorization"),
            (Operation::Responses, "/responses", "Authorization"),
            (Operation::Messages, "/anthropic/v1/messages", "x-api-key"),
            (Operation::Models, "/models", "Authorization"),
        ] {
            assert_eq!(
                deepseek.request_target(operation, None, true).unwrap(),
                path
            );
            assert_eq!(deepseek.auth_header(operation), auth);
        }
        for (provider_type, operation, suffix, auth) in [
            (
                "openai_compatible",
                Operation::Chat,
                "chat/completions",
                "Authorization",
            ),
            (
                "openai_responses",
                Operation::Responses,
                "responses",
                "Authorization",
            ),
            (
                "anthropic_messages",
                Operation::Messages,
                "messages",
                "x-api-key",
            ),
            (
                "ollama_native",
                Operation::OllamaChat,
                "chat",
                "Authorization",
            ),
        ] {
            let profile = custom(provider_type, "https://provider.example:8443/prefix/v1");
            assert_eq!(
                profile.request_target(operation, None, true).unwrap(),
                format!("/prefix/v1/{suffix}")
            );
            assert_eq!(profile.auth_header(operation), auth);
            assert_eq!(profile.connect_target()["port"], 8443);
            assert_eq!(profile.authority(), "provider.example:8443");
        }
        let gemini = custom(
            "google_gemini",
            "https://generativelanguage.googleapis.com/v1beta/",
        );
        assert_eq!(gemini.auth_header(Operation::Models), "x-goog-api-key");
        assert_eq!(
            gemini
                .request_target(Operation::Generate, Some("models/a/b?c#d%"), true)
                .unwrap(),
            "/v1beta/models/a%2Fb%3Fc%23d%25:streamGenerateContent?alt=sse"
        );
        assert_eq!(
            gemini
                .request_target(Operation::Generate, Some("gemini"), false)
                .unwrap(),
            "/v1beta/models/gemini:generateContent"
        );
        assert_eq!(
            custom("ollama_native", "https://ollama.com/api/")
                .request_target(Operation::Models, None, false)
                .unwrap(),
            "/api/tags"
        );
    }

    #[test]
    fn rejects_configuration_and_operation_ambiguity() {
        for base in [
            "http://provider.example/v1",
            "https://user@provider.example/v1",
            "https://provider.example/v1?key=value",
            "https://provider.example/v1#fragment",
            "https://provider.example:0/v1",
            "https://provider.example/\r\nInjected",
            "https:\\provider.example/v1",
        ] {
            assert!(
                ProviderProfile::from_metadata(
                    CUSTOM_PROFILE_ID,
                    Some(&json!({"provider_type":"openai_compatible","base_url":base}))
                )
                .is_err(),
                "{base:?}"
            );
        }
        assert!(
            ProviderProfile::from_metadata(crate::store::PROFILE_ID, Some(&json!({}))).is_err()
        );
        assert!(ProviderProfile::from_metadata(CUSTOM_PROFILE_ID, None).is_err());
        let gemini = custom("google_gemini", "https://provider.example/v1/");
        assert!(
            gemini
                .request_target(Operation::Generate, None, true)
                .is_err()
        );
        assert!(gemini.request_target(Operation::Chat, None, true).is_err());
        assert!(
            gemini
                .request_target(Operation::Models, Some("model"), false)
                .is_err()
        );
        let ipv6 = custom("openai_compatible", "https://[2001:db8::1]:8443/v1/");
        assert_eq!(ipv6.host(), "2001:db8::1");
        assert_eq!(ipv6.authority(), "[2001:db8::1]:8443");
    }

    #[test]
    fn url_and_model_limits_hold_after_normalization() {
        let prefix = "https://provider.example/";
        let base_url = format!("{}{}/", prefix, "a".repeat(1024 - prefix.len() - 1));
        let profile = custom("google_gemini", &base_url);
        assert_eq!(
            profile.config().unwrap()["base_url"]
                .as_str()
                .unwrap()
                .len(),
            1024
        );
        let without_slash = format!("{}{}", prefix, "a".repeat(1024 - prefix.len()));
        assert!(
            ProviderProfile::from_metadata(
                CUSTOM_PROFILE_ID,
                Some(&json!({"provider_type":"google_gemini","base_url":without_slash}))
            )
            .is_err()
        );
        let model = "a".repeat(256);
        assert!(
            profile
                .request_target(Operation::Generate, Some(&model), true)
                .is_ok()
        );
        assert!(
            profile
                .request_target(Operation::Generate, Some(&(model + "a")), true)
                .is_err()
        );
        for model in ["models/", "bad\r\nmodel", "bad\0model"] {
            assert!(
                profile
                    .request_target(Operation::Generate, Some(model), true)
                    .is_err()
            );
        }
        let normalized = custom("openai_compatible", "https://PROVIDER.EXAMPLE:443/v1");
        assert_eq!(
            normalized.config().unwrap()["base_url"],
            "https://provider.example/v1/"
        );
    }
}
