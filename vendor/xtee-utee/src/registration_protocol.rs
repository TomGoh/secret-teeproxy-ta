// SPDX-License-Identifier: Apache-2.0
//! TA registration wire extension, mirrored by xtee-utee and vsock-manager.
//!
//! Postcard variant 0 preserves teec-protocol 0.2.0 TARequest::Register exactly.
//! Variant 1 reports a Create error before a listener exists. The sender stays
//! alive until the manager acknowledges with one byte (1 accepted, 0 rejected),
//! so child reaping cannot race ahead of processing the failure report.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum RegistrationRequest {
    Register {
        uuid: String,
        instance_id: u32,
        socket_path: String,
        is_single_instance: bool,
        is_multi_session: bool,
        is_instance_keep_alive: bool,
    },
    CreateFailed {
        uuid: String,
        instance_id: u32,
        result: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_preserves_legacy_wire() {
        let legacy = teec_protocol::TARequest::Register {
            uuid: "ta".into(),
            instance_id: 7,
            socket_path: "/tmp/ta.7.sock".into(),
            is_single_instance: true,
            is_multi_session: false,
            is_instance_keep_alive: true,
        };
        let bytes = postcard::to_vec::<_, 1024>(&legacy).unwrap();
        let request: RegistrationRequest = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(postcard::to_vec::<_, 1024>(&request).unwrap(), bytes);
        assert!(matches!(
            request,
            RegistrationRequest::Register { instance_id: 7, .. }
        ));
    }

    #[test]
    fn create_failure_wire_golden() {
        let request = RegistrationRequest::CreateFailed {
            uuid: "ta".into(),
            instance_id: 7,
            result: 0xffff0000,
        };
        // variant 1, two-byte UUID, instance 7, GENERIC in postcard varint form.
        let golden = [1, 2, b't', b'a', 7, 128, 128, 252, 255, 15];
        assert_eq!(postcard::to_vec::<_, 1024>(&request).unwrap(), golden);
        assert!(matches!(
            postcard::from_bytes::<RegistrationRequest>(&golden).unwrap(),
            RegistrationRequest::CreateFailed {
                instance_id: 7,
                result: 0xffff0000,
                ..
            }
        ));
    }
}
