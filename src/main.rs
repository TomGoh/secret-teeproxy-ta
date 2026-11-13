mod ta_heap;

use secret_teeproxy_ta::{
    app::{App, Session, StoreClient},
    gp::GpPersistence,
    store::Vault,
    wire,
};
use std::sync::{Arc, Mutex};
use xtee_utee::ta_manager::{TAManager, TrustedApplication};
use xtee_utee::{ParamType, Parameters};
use zeroize::Zeroizing;

struct SecretTa {
    app: Arc<App>,
}
impl TrustedApplication for SecretTa {
    const IS_SINGLE_INSTANCE: bool = true;
    const IS_MULTI_SESSION: bool = true;
    const IS_INSTANCE_KEEP_ALIVE: bool = true;
    type SessionContext = Arc<Mutex<Session>>;
    fn create(&self) -> xtee_utee::error::Result<()> {
        Ok(())
    }
    fn destroy(&self) -> xtee_utee::error::Result<()> {
        Ok(())
    }
    fn open_session(&self, _: &mut Parameters) -> xtee_utee::error::Result<Self::SessionContext> {
        self.app
            .open_session()
            .map_err(|_| xtee_utee::error::Error::Busy)
    }
    fn close_session(&self, ctx: &mut Self::SessionContext) -> xtee_utee::error::Result<()> {
        let mut session = ctx.lock().map_err(|_| xtee_utee::error::Error::Generic)?;
        self.app.close_session(&mut session);
        Ok(())
    }
    fn invoke_command(
        &self,
        cmd: u32,
        params: &mut Parameters,
        ctx: &mut Self::SessionContext,
    ) -> xtee_utee::error::Result<()> {
        // GP input-only bytes are consumed locally and must not be echoed in
        // responses. Taking ownership before validation covers every return path.
        let input = Zeroizing::new(std::mem::take(&mut params.0.param.data));
        if cmd != wire::CMD_EXCHANGE
            || params.0.param_type != ParamType::MemrefInput
            || params.1.param_type != ParamType::MemrefOutput
            || params.2.param_type != ParamType::ValueOutput
            || params.3.param_type != ParamType::None
        {
            eprintln!(
                "LSP GP parameter rejection cmd={cmd:#010x} types={:#x},{:#x},{:#x},{:#x}",
                params.0.param_type as u32,
                params.1.param_type as u32,
                params.2.param_type as u32,
                params.3.param_type as u32,
            );
            return Err(xtee_utee::error::Error::BadParameters);
        }
        params.1.param.data.clear();
        if params.1.param.values.a < wire::OUTPUT_FRAME_MAX as u32 {
            params.2.param.values.a = wire::E_OUTPUT_CAPACITY;
            params.2.param.values.b = wire::OUTPUT_FRAME_MAX as u32;
            return Ok(());
        }
        let mut session = ctx.lock().map_err(|_| xtee_utee::error::Error::Generic)?;
        let reply = self
            .app
            .exchange(&input, &mut session)
            .map_err(|error| {
                let opcode = input.get(8..10).map(|bytes| {
                    u16::from_le_bytes([bytes[0], bytes[1]])
                });
                eprintln!(
                    "LSP GP exchange rejection status={:#010x} detail={} input_len={} opcode={opcode:?}",
                    error.status,
                    error.detail,
                    input.len(),
                );
                xtee_utee::error::Error::BadParameters
            })?;
        params.2.param.values.a = u32::from_le_bytes(
            reply[48..52]
                .try_into()
                .map_err(|_| xtee_utee::error::Error::Generic)?,
        );
        params.2.param.values.b = reply.len() as u32;
        params.1.param.data = reply;
        Ok(())
    }
}

fn run() -> Result<(), String> {
    if std::env::args().any(|s| s == "--initialize-vault") {
        return std::thread::Builder::new()
            .name("lsp-initialize".into())
            .spawn(|| {
                let persistence = GpPersistence::open(true)?;
                let id = persistence.vault_id();
                let vault = Vault::initialize(persistence, id).map_err(|e| e.to_string())?;
                drop(vault);
                println!("LSP vault initialization complete");
                Ok(())
            })
            .map_err(|e| e.to_string())?
            .join()
            .map_err(|_| "storage initialization thread failed".to_string())?;
    }
    let store = StoreClient::start(
        || {
            let persistence = GpPersistence::open(false)?;
            let id = persistence.vault_id();
            Ok((persistence, id))
        },
        false,
    )?;
    let app = App::new(store);
    let mut manager = TAManager::new(SecretTa { app }, wire::TA_UUID);
    manager.run_ta().map_err(|e| e.to_string())
}
fn main() {
    xtee_utee::logger::init_with_trace_level(2);
    if let Err(error) = run() {
        eprintln!("LSP startup failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secret_teeproxy_ta::store::Persistence;
    use serde_json::json;

    #[derive(Default)]
    struct Memory(Option<Vec<u8>>);
    impl Persistence for Memory {
        fn load(&mut self) -> Result<Option<Vec<u8>>, String> { Ok(self.0.clone()) }
        fn commit(&mut self, bytes: &[u8]) -> Result<(), String> {
            self.0 = Some(bytes.to_vec());
            Ok(())
        }
    }

    #[test]
    fn gp_input_only_is_consumed_before_success_capacity_and_error_returns() {
        let app = App::new(StoreClient::start(|| Ok((Memory::default(), [7; 16])), true).unwrap());
        let ta = SecretTa { app };
        let hello = wire::Frame {
            opcode: wire::HELLO,
            request_id: [0; 16],
            call_seq: 1,
            status: wire::OK,
            metadata: json!({"role":"request","supported_versions":[{"major":1,"minor":0}]}),
            payload: Vec::new(),
        }.encode_request().unwrap();
        for (command, capacity, input, expected_success) in [
            (wire::CMD_EXCHANGE, wire::OUTPUT_FRAME_MAX, hello, true),
            (wire::CMD_EXCHANGE, 1, vec![0xa5; wire::INPUT_FRAME_MAX], true),
            (wire::CMD_EXCHANGE, wire::OUTPUT_FRAME_MAX, vec![0xa5; wire::INPUT_FRAME_MAX], false),
            (0, wire::OUTPUT_FRAME_MAX, vec![0xa5; wire::INPUT_FRAME_MAX], false),
        ] {
            let mut parameters = Parameters::default();
            parameters.0.param_type = ParamType::MemrefInput;
            parameters.0.param.data = input;
            parameters.0.param.values.a = 17;
            parameters.0.param.values.b = 19;
            parameters.1.param_type = ParamType::MemrefOutput;
            parameters.1.param.values.a = capacity as u32;
            parameters.2.param_type = ParamType::ValueOutput;
            let mut context = ta.app.open_session().unwrap();
            let result = ta.invoke_command(command, &mut parameters, &mut context);
            assert_eq!(result.is_ok(), expected_success);
            assert!(parameters.0.param.data.is_empty());
            assert_eq!(parameters.0.param_type, ParamType::MemrefInput);
            assert_eq!(parameters.0.param.values.a, 17);
            assert_eq!(parameters.0.param.values.b, 19);
            assert!(parameters.1.param.data.len() <= wire::OUTPUT_FRAME_MAX);
            assert_eq!(parameters.1.param.values.a, capacity as u32);
        }
    }
}
include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));
