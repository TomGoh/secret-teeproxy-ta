use crate::{
    api::{
        tee_api_generic::{copy_param, update_out_param},
        tee_api_panic::TEE_Panic,
    },
    syscalls::{
        seam::{invoke_ta_command, open_ta_session},
        syscall_table::_utee_close_ta_session,
    },
    tee_api_defines::{TEE_HANDLE_NULL, TEE_NUM_PARAMS, TEE_SUCCESS},
    tee_api_types::{TEE_Param, TEE_Result, TEE_TASessionHandle, TEE_UUID},
    utee_types::utee_params,
};

/// Opens a session towards another TA.
///
/// The syscall receives the address of the `utee_params` built from
/// `params` (`&mut up`); the kernel reads the input parameters from, and
/// writes output parameters back to, that same address.
#[unsafe(no_mangle)]
pub extern "C" fn TEE_OpenTASession(
    destination: *const TEE_UUID,
    cancellationRequestTimeout: u32,
    paramTypes: u32,
    params: *mut [TEE_Param; TEE_NUM_PARAMS as usize],
    session: *mut TEE_TASessionHandle,
    returnOrigin: *mut u32,
) -> TEE_Result {
    let mut up = utee_params {
        types: 0,
        vals: [0; _],
    };
    copy_param(&mut up, paramTypes, params);
    let res = unsafe {
        open_ta_session(
            destination,
            cancellationRequestTimeout as _,
            &mut up as _,
            session as _,
            returnOrigin as _,
        )
    };
    update_out_param(params, &up);

    res as TEE_Result
}

#[unsafe(no_mangle)]
pub extern "C" fn TEE_CloseTASession(session: TEE_TASessionHandle) {
    if session != TEE_HANDLE_NULL as _ {
        let res = unsafe { _utee_close_ta_session(session as _) } as u32;

        if res != TEE_SUCCESS {
            TEE_Panic(res);
        }
    }
}

/// Invokes a command on another TA through an open session.
///
/// The syscall's fourth argument must be the address of the `utee_params`
/// built from `params` (`&mut up`), not the session handle; the kernel
/// reads the input parameters from, and writes output parameters back to,
/// that same address.
#[unsafe(no_mangle)]
pub extern "C" fn TEE_InvokeTACommand(
    session: TEE_TASessionHandle,
    cancellationRequestTimeout: u32,
    commandID: u32,
    paramTypes: u32,
    params: *mut [TEE_Param; TEE_NUM_PARAMS as usize],
    returnOrigin: *mut u32,
) -> TEE_Result {
    let mut up = utee_params {
        types: 0,
        vals: [0; _],
    };
    copy_param(&mut up, paramTypes, params);
    let res = unsafe {
        invoke_ta_command(
            session as _,
            cancellationRequestTimeout as _,
            commandID as _,
            &mut up as _,
            returnOrigin as _,
        )
    };
    update_out_param(params, &up);

    res as TEE_Result
}

#[cfg(test)]
mod inter_ta_syscall_arg_tests {
    use super::*;
    use crate::syscalls::seam::{
        EMULATED_OPEN_SESSION_HANDLE, EMULATED_OUTPUT_VALS, take_last_captured,
    };
    use crate::syscalls::syscall_table::{TEE_SCN_INVOKE_TA_COMMAND, TEE_SCN_OPEN_TA_SESSION};
    use crate::tee_api_defines::{
        TEE_ORIGIN_TEE, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPES,
    };
    use crate::tee_api_types::{Memref, Value};

    #[test]
    fn invoke_ta_command_passes_real_params_address_to_syscall() {
        // Back the session handle with utee_params-sized writable memory so
        // the historical bug (the session value handed to the kernel as the
        // params address) shows up as an assertion mismatch instead of a
        // wild pointer access.
        let mut fake_session_storage = utee_params {
            types: 0,
            vals: [0; 8],
        };
        let session: TEE_TASessionHandle =
            (&mut fake_session_storage as *mut utee_params) as TEE_TASessionHandle;
        let session_addr = session as usize;

        let value_input_a: u32 = 0x1122_3344;
        let value_input_b: u32 = 0x5566_7788;
        let mut out_buffer = [0u8; 16];
        let out_buffer_addr = out_buffer.as_mut_ptr() as usize;
        let param_types = TEE_PARAM_TYPES(
            TEE_PARAM_TYPE_VALUE_INPUT,
            TEE_PARAM_TYPE_MEMREF_OUTPUT,
            TEE_PARAM_TYPE_VALUE_OUTPUT,
            TEE_PARAM_TYPE_NONE,
        );
        let mut params: [TEE_Param; TEE_NUM_PARAMS as usize] = [
            TEE_Param {
                value: Value {
                    a: value_input_a,
                    b: value_input_b,
                },
            },
            TEE_Param {
                memref: Memref {
                    buffer: out_buffer.as_mut_ptr() as *mut _,
                    size: out_buffer.len(),
                },
            },
            TEE_Param {
                value: Value { a: 0, b: 0 },
            },
            TEE_Param {
                value: Value { a: 0, b: 0 },
            },
        ];

        let cancellation_timeout: u32 = 0xABCD;
        let command_id: u32 = 7;
        let mut return_origin: u32 = 0xFFFF_FFFF;
        let return_origin_addr = &mut return_origin as *mut u32 as usize;

        let result = TEE_InvokeTACommand(
            session,
            cancellation_timeout,
            command_id,
            param_types,
            &mut params as *mut _,
            &mut return_origin,
        );

        // The emulated syscall returned success through the real call path.
        assert_eq!(result, TEE_SUCCESS);
        assert_eq!(return_origin, TEE_ORIGIN_TEE);

        let captured = take_last_captured().expect("invoke must use the syscall seam");
        assert_eq!(captured.nr, TEE_SCN_INVOKE_TA_COMMAND);
        // The other argument words keep their syscall ABI meanings.
        assert_eq!(captured.args[0], session_addr);
        assert_eq!(captured.args[1], cancellation_timeout as usize);
        assert_eq!(captured.args[2], command_id as usize);
        assert_eq!(captured.args[4], return_origin_addr);
        // Supplementary canary for the historical bug: the params word must
        // not be the session value itself. The primary proof that this word
        // is the address of the real params structure is the snapshot
        // content equality plus the output write-back round-trip below.
        assert_ne!(captured.args[3], session_addr);

        // Primary assertion: the fourth argument word is the address of the
        // real utee_params built from the caller's TEE_Param array, so the
        // kernel reads the actual parameter structure. The expected layout
        // follows the utee_params ABI (types plus four (a, b) pairs) and is
        // derived here independently of copy_param.
        let expected = utee_params {
            types: param_types as u64,
            vals: [
                value_input_a as u64,
                value_input_b as u64,
                out_buffer_addr as u64,
                out_buffer.len() as u64,
                0,
                0,
                0,
                0,
            ],
        };
        assert_eq!(captured.params_snapshot.types, expected.types);
        assert_eq!(captured.params_snapshot.vals, expected.vals);

        // Round-trip: the emulated kernel wrote output values through the
        // params address received by the syscall, and the caller's output
        // parameters observe them, proving that address is the very
        // structure the SDK write-back path reads after the syscall.
        // SAFETY: update_out_param wrote the matching union variant for each
        // of these slots, so reading the same variant is valid.
        assert_eq!(
            unsafe { params[1].memref.buffer } as usize,
            EMULATED_OUTPUT_VALS[2] as usize
        );
        assert_eq!(
            unsafe { params[1].memref.size },
            EMULATED_OUTPUT_VALS[3] as usize
        );
        assert_eq!(unsafe { params[2].value.a }, EMULATED_OUTPUT_VALS[4] as u32);
        assert_eq!(unsafe { params[2].value.b }, EMULATED_OUTPUT_VALS[5] as u32);
        // Input parameters are not overwritten by the write-back.
        assert_eq!(unsafe { params[0].value.a }, value_input_a);
        assert_eq!(unsafe { params[0].value.b }, value_input_b);
    }

    #[test]
    fn open_ta_session_passes_five_arguments_unchanged() {
        let mut session_out: TEE_TASessionHandle = core::ptr::null_mut();
        let session_ptr_addr = &mut session_out as *mut TEE_TASessionHandle as usize;
        let destination = TEE_UUID {
            timeLow: 0x936D_A01F,
            timeMid: 0x9ABD,
            timeHiAndVersion: 0x4D9D,
            clockSeqAndNode: [0x80, 0xC7, 0x02, 0xAF, 0x85, 0xC8, 0x22, 0xA8],
        };
        let destination_addr = &destination as *const TEE_UUID as usize;

        let value_a: u32 = 0x1234_5678;
        let value_b: u32 = 0x90AB_CDEF;
        let param_types = TEE_PARAM_TYPES(
            TEE_PARAM_TYPE_VALUE_INPUT,
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE,
        );
        let mut params: [TEE_Param; TEE_NUM_PARAMS as usize] = [
            TEE_Param {
                value: Value {
                    a: value_a,
                    b: value_b,
                },
            },
            TEE_Param {
                value: Value { a: 0, b: 0 },
            },
            TEE_Param {
                value: Value { a: 0, b: 0 },
            },
            TEE_Param {
                value: Value { a: 0, b: 0 },
            },
        ];

        let cancellation_timeout: u32 = 1000;
        let mut return_origin: u32 = 0xFFFF_FFFF;
        let return_origin_addr = &mut return_origin as *mut u32 as usize;

        let result = TEE_OpenTASession(
            &destination,
            cancellation_timeout,
            param_types,
            &mut params as *mut _,
            &mut session_out,
            &mut return_origin,
        );

        // The emulated kernel reported success through the real call path.
        assert_eq!(result, TEE_SUCCESS);
        assert_eq!(return_origin, TEE_ORIGIN_TEE);
        assert_eq!(session_out as usize, EMULATED_OPEN_SESSION_HANDLE as usize);

        let captured = take_last_captured().expect("open must use the syscall seam");
        assert_eq!(captured.nr, TEE_SCN_OPEN_TA_SESSION);
        // The normal Open passing paradigm: destination, cancellation
        // timeout, params address, session out-pointer, returnOrigin.
        assert_eq!(captured.args[0], destination_addr);
        assert_eq!(captured.args[1], cancellation_timeout as usize);
        assert_eq!(captured.args[3], session_ptr_addr);
        assert_eq!(captured.args[4], return_origin_addr);

        // The params word points at the real utee_params built by the API.
        let expected = utee_params {
            types: param_types as u64,
            vals: [value_a as u64, value_b as u64, 0, 0, 0, 0, 0, 0],
        };
        assert_eq!(captured.params_snapshot.types, expected.types);
        assert_eq!(captured.params_snapshot.vals, expected.vals);
    }
}
