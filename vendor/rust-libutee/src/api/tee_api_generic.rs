use crate::{
    tee_api_defines::{
        TEE_NUM_PARAMS, TEE_PARAM_TYPE_GET, TEE_PARAM_TYPE_MEMREF_INOUT,
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_VALUE_INOUT,
        TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_OUTPUT,
    },
    tee_api_types::{Memref, TEE_Param},
    utee_types::utee_params,
};

pub(crate) fn copy_param(
    up: &mut utee_params,
    paramTypes: u32,
    params: *mut [TEE_Param; TEE_NUM_PARAMS as usize],
) {
    up.types = paramTypes as u64;
    for i in 0..TEE_NUM_PARAMS as usize {
        // `paramTypes == 0` 时上游不读取 `params`，允许传入空指针。
        let (a, b) = match TEE_PARAM_TYPE_GET(paramTypes, i as u32) {
            TEE_PARAM_TYPE_VALUE_INPUT | TEE_PARAM_TYPE_VALUE_INOUT => {
                let params = unsafe { &*params };
                unsafe { (params[i].value.a as u64, params[i].value.b as u64) }
            }
            TEE_PARAM_TYPE_MEMREF_OUTPUT
            | TEE_PARAM_TYPE_MEMREF_INOUT
            | TEE_PARAM_TYPE_MEMREF_INPUT => {
                let params = unsafe { &*params };
                let memref = unsafe { params[i].memref };
                (memref.buffer as u64, memref.size as u64)
            }
            _ => (0, 0),
        };

        up.vals[i * 2] = a;
        up.vals[i * 2 + 1] = b;
    }
}

pub(crate) fn update_out_param(
    params: *mut [TEE_Param; TEE_NUM_PARAMS as usize],
    up: &utee_params,
) {
    for i in 0..TEE_NUM_PARAMS as usize {
        let a = up.vals[i * 2];
        let b = up.vals[i * 2 + 1];
        match TEE_PARAM_TYPE_GET(up.types as u32, i as u32) {
            TEE_PARAM_TYPE_VALUE_OUTPUT | TEE_PARAM_TYPE_VALUE_INOUT => {
                let params = unsafe { &mut *params };
                params[i].value.a = a as u32;
                params[i].value.b = b as u32;
            }
            TEE_PARAM_TYPE_MEMREF_OUTPUT | TEE_PARAM_TYPE_MEMREF_INOUT => {
                let params = unsafe { &mut *params };
                params[i].memref = Memref {
                    buffer: a as _,
                    size: b as usize,
                }
            }
            _ => {}
        };
    }
}
