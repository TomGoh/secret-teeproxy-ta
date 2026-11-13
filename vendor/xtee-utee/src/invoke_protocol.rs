// SPDX-License-Identifier: Apache-2.0
//! Manager-to-TA extension. The first four variants exactly mirror
//! teec-protocol 0.2; timed Invoke is appended as variant 4. Old responses apply.
use serde::{Deserialize, Serialize};
use teec_protocol::{CaAuthInfo, Parameters};

#[derive(Serialize, Deserialize)]
pub(crate) enum TaRequest {
    OpenSession {
        uuid: String,
        connection_method: u32,
        params: Parameters,
        ca_auth_info: Option<CaAuthInfo>,
    },
    CloseSession {
        session_id: u32,
    },
    InvokeCommand {
        session_id: u32,
        cmd_id: u32,
        params: Parameters,
    },
    RequestCancellation {
        session_id: u32,
    },
    InvokeCommandWithTimeout {
        session_id: u32,
        cmd_id: u32,
        params: Parameters,
        deadline_ns: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_requests_keep_their_bytes() {
        use teec_protocol::TEE_Request as Legacy;
        for request in [
            Legacy::OpenSession {
                uuid: "ta".into(),
                connection_method: 0,
                params: Parameters::default(),
                ca_auth_info: None,
            },
            Legacy::CloseSession { session_id: 7 },
            Legacy::InvokeCommand {
                session_id: 7,
                cmd_id: 2,
                params: Parameters::default(),
            },
            Legacy::RequestCancellation { session_id: 7 },
        ] {
            let bytes = postcard::to_allocvec(&request).unwrap();
            let decoded: TaRequest = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(postcard::to_allocvec(&decoded).unwrap(), bytes);
        }
    }
    #[test]
    fn timed_invoke_matches_independent_wire() {
        let request = TaRequest::InvokeCommandWithTimeout {
            session_id: 7,
            cmd_id: 2,
            params: Parameters::default(),
            deadline_ns: 1234,
        };
        const EXPECTED: &[u8] = &[
            4, 7, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 210, 9,
        ];
        let expected = EXPECTED;
        assert_eq!(postcard::to_allocvec(&request).unwrap(), expected);
        assert!(matches!(
            postcard::from_bytes::<TaRequest>(expected).unwrap(),
            TaRequest::InvokeCommandWithTimeout {
                deadline_ns: 1234,
                ..
            }
        ));
    }
}
