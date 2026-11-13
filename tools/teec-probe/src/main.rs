//! Test-only interoperability executable using the reusable backup CA core.
use lsp_backup_ca::driver as suites;
use lsp_backup_ca::*;
use serde_json::json;

struct Args {
    cid: u32,
    port: u32,
    mode: String,
    upstream_ip: Option<std::net::IpAddr>,
    namespace: String,
    reference: Option<String>,
    operation: Option<String>,
    version: u64,
    model: String,
    operation_kind: String,
    stream: bool,
    network_chunk_size: usize,
    profile_id: String,
    provider_type: Option<String>,
    base_url: Option<String>,
}
fn args() -> Result<Args> {
    let mut cid = None;
    let mut port = 10099;
    let mut mode = "--probe".to_string();
    let mut upstream_ip = None;
    let mut explicit_mode = false;
    let mut namespace = "lsp-probe".to_string();
    let mut reference = None;
    let mut operation = None;
    let mut version = 1;
    let mut model = "deepseek-flash".to_string();
    let mut operation_kind = "CHAT".to_string();
    let mut stream = false;
    let mut network_chunk_size = 8192;
    let mut profile_id = "deepseek-prod-v1".to_owned();
    let mut provider_type = None;
    let mut base_url = None;
    let mut values = std::env::args().skip(1);
    while let Some(value) = values.next() {
        match value.as_str() {
            "--cid"=>cid=Some(values.next().ok_or("missing CID")?.parse().map_err(|_|"invalid CID")?),
            "--port"=>port=values.next().ok_or("missing port")?.parse().map_err(|_|"invalid port")?,
            "--probe"|"--test-suite"|"--parallel-suite"|"--fault-suite"|"--hold-upload"|"--hold-tls"|"--models"|"--provision-stdin"|"--chat"|"--chat-stream"|"--parallel-chat"|"--real-models"=>{
                if value == "--chat-stream" { stream = true; }
                if (mode == "--parallel-chat" && value == "--chat-stream") || (mode == "--chat-stream" && value == "--parallel-chat") {
                    mode = "--parallel-chat".into();
                } else {
                    require(!explicit_mode,"choose one probe mode")?;
                    mode=value;explicit_mode=true;
                }
            }
            "--upstream-ip"=>upstream_ip=Some(values.next().ok_or("missing upstream IP")?.parse().map_err(|_|"invalid upstream IP")?),
            "--namespace"=>namespace=values.next().ok_or("missing namespace")?,
            "--credential-ref"=>reference=Some(values.next().ok_or("missing credential reference")?),
            "--operation-id"=>operation=Some(values.next().ok_or("missing operation ID")?),
            "--expected-version"=>version=values.next().ok_or("missing credential version")?.parse().map_err(|_|"invalid credential version")?,
            "--network-chunk-size"=>network_chunk_size=values.next().ok_or("missing network chunk size")?.parse().map_err(|_|"invalid network chunk size")?,
            "--profile-id"=>profile_id=values.next().ok_or("missing profile ID")?,
            "--provider-type"=>provider_type=Some(values.next().ok_or("missing provider type")?),
            "--base-url"=>base_url=Some(values.next().ok_or("missing base URL")?),
            "--operation"=>operation_kind=values.next().ok_or("missing operation")?,
            "--model"=>model=values.next().ok_or("missing model")?,
            "--help"=>return Err("usage lsp-teec-probe --cid <actual-vm-cid> [--port 10099] [--probe|--test-suite|--parallel-suite|--fault-suite|--hold-upload|--hold-tls|--models|--chat|--chat-stream|--parallel-chat|--real-models] [--profile-id PROFILE] [--provider-type TYPE --base-url HTTPS_BASE for custom provisioning] [--operation CHAT|RESPONSES|MESSAGES] [--upstream-ip IP] [--network-chunk-size 1..16384]".into()),
            _=>return Err("unknown CLI argument".into()),
        }
    }
    let cid = cid.ok_or("--cid is required")?;
    require(cid > 2 && port > 0, "invalid VSOCK endpoint")?;
    require(
        provider_type.is_some() == base_url.is_some(),
        "provider type and base URL must be supplied together",
    )?;
    if provider_type.is_some() {
        require(
            mode == "--provision-stdin" && profile_id == "custom-provider-v1",
            "provider configuration requires custom-profile provisioning",
        )?;
    }
    if mode == "--provision-stdin" && profile_id == "custom-provider-v1" {
        require(
            provider_type.is_some(),
            "custom profile requires provider configuration",
        )?;
    }
    Ok(Args {
        cid,
        port,
        mode,
        upstream_ip,
        namespace,
        reference,
        operation,
        version,
        model,
        operation_kind,
        stream,
        network_chunk_size,
        profile_id,
        provider_type,
        base_url,
    })
}

fn run() -> Result<()> {
    let args = args()?;
    cc_teec::configure_vsock_endpoint(args.cid, args.port).map_err(str::to_owned)?;
    let auth = cc_teec::get_or_verify_ca();
    emit(
        json!({"check":"sdk_ca_auth","ca_uuid":auth.ca_uuid,"verified":auth.verified,"ca_sign_verify_compiled":true,
        "test_only":true,"cid":args.cid,"port":args.port}),
    );
    match args.mode.as_str() {
        "--probe" => {
            let _channel = Channel::hello("management", true)?;
        }
        "--test-suite" => suites::test_suite()?,
        "--parallel-suite" => suites::parallel_suite()?,
        "--fault-suite" => suites::fault_suite()?,
        "--hold-upload" => suites::hold_request(false)?,
        "--hold-tls" => suites::hold_request(true)?,
        "--models" => suites::models(args.upstream_ip)?,
        "--provision-stdin" => {
            use std::io::Read;
            let mut key = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin()
                .lock()
                .take(4099)
                .read_to_end(&mut key)
                .map_err(|_| "stdin credential read failed")?;
            if key.last() == Some(&b'\n') {
                key.pop();
                if key.last() == Some(&b'\r') {
                    key.pop();
                }
            }
            require(
                !key.is_empty()
                    && key.len() <= 4096
                    && std::str::from_utf8(&key).is_ok()
                    && !key.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n')),
                "invalid stdin credential bytes",
            )?;
            let reference = args
                .reference
                .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
            let operation = args
                .operation
                .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
            let result = if let (Some(provider_type), Some(base_url)) =
                (&args.provider_type, &args.base_url)
            {
                let mut management = Channel::hello("management", false)?;
                let written = management.call(CREDENTIAL_PUT,json!({"namespace":args.namespace,"credential_ref":reference,
                    "operation_id":operation,"expected_version":"0","profile_id":args.profile_id,"temporary":false,
                    "provider_config":{"provider_type":provider_type,"base_url":base_url}}),&key)?;
                require(
                    written.status == OK,
                    "custom credential PUT rejected; reconcile through QUERY",
                )?;
                let queried = management.call(
                    CREDENTIAL_QUERY,
                    json!({"namespace":args.namespace,"credential_ref":reference}),
                    &[],
                )?;
                require(
                    queried.status == OK
                        && queried.metadata["result"]["receipt"]["operation_id"] == operation
                        && queried.metadata["result"]["version"]
                            == written.metadata["result"]["version"],
                    "custom provision receipt reconciliation",
                )?;
                queried.metadata["result"].clone()
            } else {
                require(
                    args.profile_id == "deepseek-prod-v1",
                    "builtin provisioning profile unsupported",
                )?;
                suites::provision(&args.namespace, &reference, &operation, &key)?
            };
            emit(json!({"check":"credential_provisioned","ok":true,"result":result}));
        }
        "--chat" | "--chat-stream" | "--parallel-chat" | "--real-models" => {
            let reference = args.reference.ok_or("existing --credential-ref required")?;
            let chat = args.mode != "--real-models";
            let stream = args.stream;
            let random = Uuid::new_v4().simple().to_string();
            let nonce = format!("LSP_OK_{}", &random[..8]);
            let body = if chat {
                suites::chat_body(&args.operation_kind, &args.model, stream, &nonce)?
            } else {
                Vec::new()
            };
            let config = suites::RawConfig {
                namespace: args.namespace,
                profile_id: args.profile_id,
                model_id: None,
                credential_ref: reference,
                expected_version: args.version,
                operation: if chat {
                    args.operation_kind.clone()
                } else {
                    "MODELS".into()
                },
                response_mode: if stream { "sse".into() } else { "json".into() },
                overall_timeout_ms: 60000,
                max_response_bytes: 1024 * 1024,
                network_chunk_size: args.network_chunk_size,
                upstream_ip: args.upstream_ip.map(|ip| ip.to_string()),
                headers: Vec::new(),
            };
            if args.mode == "--parallel-chat" {
                suites::parallel_chat(config, &args.model, stream)?;
                emit(json!({"check":"complete","mode":args.mode,"ok":true}));
                return Ok(());
            }
            let mut channel = Channel::hello("request", false)?;
            let response = suites::request(&mut channel, &config, &body, None)?;
            require(
                response.status == 200,
                "existing credential request did not return HTTP 200",
            )?;
            let mut result = json!({"check":"existing_credential_http_complete","ok":true,"http_status":response.status,
                "body_length":response.body.len(),"body_sha256":format!("{:x}",<sha2::Sha256 as sha2::Digest>::digest(&response.body)),"transport":response.transport,"ca_metrics":response.ca_metrics});
            if chat {
                let observed =
                    suites::inspect_protocol(&response.body, stream, &nonce, &args.operation_kind)?;
                result["synthetic_nonce_observed"] = json!(true);
                result["model_stop_reason"] = observed["model_stop_reason"].clone();
                result["sse_done_observed"] = observed["sse_done_observed"].clone();
                result["protocol_terminal_observed"] =
                    observed["protocol_terminal_observed"].clone();
                result["observed_model"] = observed["observed_model"].clone();
                result["requested_model"] = json!(args.model);
            }
            emit(result);
        }
        _ => unreachable!(),
    }
    emit(json!({"check":"complete","mode":args.mode,"ok":true}));
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        emit(json!({"check":"failed","ok":false,"error":error}));
        std::process::exit(1);
    }
}
