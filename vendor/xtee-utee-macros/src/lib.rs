// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{FnArg, Item, ItemFn, ItemMod, parse_macro_input, spanned::Spanned};

#[proc_macro_attribute]
pub fn ta_create(_args: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn ta_open_session(_args: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn ta_close_session(_args: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn ta_destroy(_args: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn ta_invoke_command(_args: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn ta_acl_check(_args: TokenStream, input: TokenStream) -> TokenStream {
    input
}

/// 聚合 TA 入口函数并生成 `TrustedApplication`（socket 模型）。用法：`xtee_ta! { #[ta_create] fn create() ... ... }`，无需额外 `mod`。
///
/// 实际进程入口 `fn main()` 由 `build.rs` 里 `xtee_utee_build` 生成（默认 `TaConfig::emit_main_entry`）。
/// 在调用 `TAManager::run_ta()` 前会可选打印一行启动信息（`trace_println!`，默认开启），可在 `build.rs` 用
/// `TaConfig::... .main_entry_banner(false)` 关闭。
#[proc_macro]
pub fn xtee_ta(input: TokenStream) -> TokenStream {
    let file = parse_macro_input!(input as syn::File);
    match expand_xtee_ta_items(file.items) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// 可选：仍支持 `#[xtee_ta] mod foo { ... }`（旧写法）。
#[proc_macro_attribute]
pub fn xtee_ta_module(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_mod = parse_macro_input!(input as ItemMod);
    let ta_struct_ident = format_ident!("Ta");

    let Some((_, items)) = &mut item_mod.content else {
        return syn::Error::new(
            item_mod.span(),
            "#[xtee_ta_module] only supports inline modules",
        )
        .to_compile_error()
        .into();
    };

    match expand_xtee_ta_items_mut(items, ta_struct_ident) {
        Ok(()) => quote!(#item_mod).into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_xtee_ta_items(items: Vec<Item>) -> Result<TokenStream2, syn::Error> {
    let ta_struct_ident = format_ident!("Ta");
    let mut items = items;
    expand_xtee_ta_items_mut(&mut items, ta_struct_ident)?;
    Ok(quote! { #(#items)* })
}

fn expand_xtee_ta_items_mut(
    items: &mut Vec<Item>,
    ta_struct_ident: syn::Ident,
) -> Result<(), syn::Error> {
    let mut create_fn: Option<ItemFn> = None;
    let mut open_fn: Option<ItemFn> = None;
    let mut close_fn: Option<ItemFn> = None;
    let mut destroy_fn: Option<ItemFn> = None;
    let mut invoke_fn: Option<ItemFn> = None;
    let mut acl_fn: Option<ItemFn> = None;

    for item in items.iter_mut() {
        let Item::Fn(func) = item else {
            return Err(syn::Error::new(
                item.span(),
                "xtee_ta! only supports `fn` items (put `use` at crate root)",
            ));
        };
        let marker = extract_marker_and_strip(func);
        let Some(marker) = marker else {
            return Err(syn::Error::new(
                func.span(),
                "xtee_ta!: each `fn` must carry one of #[ta_create], #[ta_open_session], #[ta_close_session], #[ta_destroy], #[ta_invoke_command], #[ta_acl_check]",
            ));
        };
        match marker.as_str() {
            "ta_create" => {
                if create_fn.replace(func.clone()).is_some() {
                    return Err(syn::Error::new(
                        func.span(),
                        "duplicate #[ta_create] function",
                    ));
                }
            }
            "ta_open_session" => {
                if open_fn.replace(func.clone()).is_some() {
                    return Err(syn::Error::new(
                        func.span(),
                        "duplicate #[ta_open_session] function",
                    ));
                }
            }
            "ta_close_session" => {
                if close_fn.replace(func.clone()).is_some() {
                    return Err(syn::Error::new(
                        func.span(),
                        "duplicate #[ta_close_session] function",
                    ));
                }
            }
            "ta_destroy" => {
                if destroy_fn.replace(func.clone()).is_some() {
                    return Err(syn::Error::new(
                        func.span(),
                        "duplicate #[ta_destroy] function",
                    ));
                }
            }
            "ta_invoke_command" => {
                if invoke_fn.replace(func.clone()).is_some() {
                    return Err(syn::Error::new(
                        func.span(),
                        "duplicate #[ta_invoke_command] function",
                    ));
                }
            }
            "ta_acl_check" => {
                if acl_fn.replace(func.clone()).is_some() {
                    return Err(syn::Error::new(
                        func.span(),
                        "duplicate #[ta_acl_check] function",
                    ));
                }
            }
            _ => {
                return Err(syn::Error::new(
                    func.span(),
                    "unknown #[ta_*] attribute for xtee_ta!",
                ));
            }
        }
    }

    let Some(create_fn) = create_fn else {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "missing #[ta_create] function",
        ));
    };
    let Some(open_fn) = open_fn else {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "missing #[ta_open_session] function",
        ));
    };
    let Some(close_fn) = close_fn else {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "missing #[ta_close_session] function",
        ));
    };
    let Some(destroy_fn) = destroy_fn else {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "missing #[ta_destroy] function",
        ));
    };
    let Some(invoke_fn) = invoke_fn else {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "missing #[ta_invoke_command] function",
        ));
    };

    let create_ident = create_fn.sig.ident.clone();
    let destroy_ident = destroy_fn.sig.ident.clone();

    let (session_ctx_ty, open_call, close_call, invoke_call) =
        build_context_and_calls(&open_fn, &close_fn, &invoke_fn)?;

    let acl_check_impl = if let Some(acl_fn) = &acl_fn {
        if acl_fn.sig.inputs.len() != 1 {
            return Err(syn::Error::new(
                acl_fn.sig.span(),
                "#[ta_acl_check] expects fn(ca_auth_info: Option<&CaAuthInfo>)",
            ));
        }
        let acl_ident = &acl_fn.sig.ident;
        quote! {
            fn acl_check(
                &self,
                ca_auth_info: Option<&teec_protocol::CaAuthInfo>,
            ) -> xtee_utee::error::Result<()> {
                __XteeIntoTaResult::into_ta_result(#acl_ident(ca_auth_info))
            }
        }
    } else {
        quote! {}
    };

    let impl_block = quote! {
        use teec_protocol::Parameters;

        pub struct #ta_struct_ident;

        trait __XteeIntoTaResult {
            fn into_ta_result(self) -> xtee_utee::error::Result<()>;
        }

        impl __XteeIntoTaResult for () {
            fn into_ta_result(self) -> xtee_utee::error::Result<()> {
                Ok(())
            }
        }

        impl __XteeIntoTaResult for xtee_utee::error::Result<()> {
            fn into_ta_result(self) -> xtee_utee::error::Result<()> {
                self
            }
        }

        impl xtee_utee::ta_manager::TrustedApplication for #ta_struct_ident {
            // These flags are generated into `user_ta_header.rs` by `xtee-utee-build`.
            // `main.rs` includes that header after `xtee_ta!` expansion.
            const IS_SINGLE_INSTANCE: bool = IS_SINGLE_INSTANCE;
            const IS_MULTI_SESSION: bool = IS_MULTI_SESSION;
            const IS_INSTANCE_KEEP_ALIVE: bool = IS_KEEP_ALIVE;

            type SessionContext = #session_ctx_ty;

            fn create(&self) -> xtee_utee::error::Result<()> {
                __XteeIntoTaResult::into_ta_result(#create_ident())
            }

            #acl_check_impl

            fn open_session(
                &self,
                params: &mut Parameters,
            ) -> xtee_utee::error::Result<Self::SessionContext> {
                #open_call
            }

            fn close_session(
                &self,
                ctx: &mut Self::SessionContext,
            ) -> xtee_utee::error::Result<()> {
                __XteeIntoTaResult::into_ta_result(#close_call)
            }

            fn destroy(&self) -> xtee_utee::error::Result<()> {
                __XteeIntoTaResult::into_ta_result(#destroy_ident())
            }

            fn invoke_command(
                &self,
                cmd_id: u32,
                params: &mut Parameters,
                ctx: &mut Self::SessionContext,
            ) -> xtee_utee::error::Result<()> {
                __XteeIntoTaResult::into_ta_result(#invoke_call)
            }
        }
    };

    let parsed: syn::File = syn::parse2(impl_block).map_err(|e| {
        syn::Error::new(
            proc_macro2::Span::call_site(),
            format!("xtee_ta: failed to parse generated items: {e}"),
        )
    })?;
    for item in parsed.items {
        items.push(item);
    }

    Ok(())
}

fn extract_marker_and_strip(func: &mut ItemFn) -> Option<String> {
    let mut marker: Option<String> = None;
    func.attrs.retain(|attr| {
        let Some(last) = attr.path().segments.last() else {
            return true;
        };
        let name = last.ident.to_string();
        let is_marker = matches!(
            name.as_str(),
            "ta_create"
                | "ta_open_session"
                | "ta_close_session"
                | "ta_destroy"
                | "ta_invoke_command"
                | "ta_acl_check"
        );
        if is_marker {
            marker = Some(name);
            false
        } else {
            true
        }
    });
    marker
}

fn build_context_and_calls(
    open_fn: &ItemFn,
    close_fn: &ItemFn,
    invoke_fn: &ItemFn,
) -> Result<(TokenStream2, TokenStream2, TokenStream2, TokenStream2), syn::Error> {
    let open_arg_count = open_fn.sig.inputs.len();
    let close_arg_count = close_fn.sig.inputs.len();
    let invoke_arg_count = invoke_fn.sig.inputs.len();

    if !(open_arg_count == 1 || open_arg_count == 2) {
        return Err(syn::Error::new(
            open_fn.sig.span(),
            "#[ta_open_session] expects fn(&mut Parameters) or fn(&mut Parameters, &mut T)",
        ));
    }

    if !(close_arg_count == 0 || close_arg_count == 1) {
        return Err(syn::Error::new(
            close_fn.sig.span(),
            "#[ta_close_session] expects fn() or fn(&mut T)",
        ));
    }

    if !(invoke_arg_count == 2 || invoke_arg_count == 3) {
        return Err(syn::Error::new(
            invoke_fn.sig.span(),
            "#[ta_invoke_command] expects fn(cmd_id, &mut Parameters) or fn(&mut T, cmd_id, &mut Parameters)",
        ));
    }

    let open_ident = &open_fn.sig.ident;
    let close_ident = &close_fn.sig.ident;
    let invoke_ident = &invoke_fn.sig.ident;

    if open_arg_count == 1 {
        if close_arg_count != 0 || invoke_arg_count != 2 {
            return Err(syn::Error::new(
                open_fn.sig.span(),
                "no-session-context mode requires close_session() and invoke_command(cmd_id, params)",
            ));
        }
        let session_ctx_ty = quote! { () };
        let open_call = quote! {
            __XteeIntoTaResult::into_ta_result(#open_ident(params))?;
            Ok(())
        };
        let close_call = quote! { #close_ident() };
        let invoke_call = quote! { #invoke_ident(cmd_id, params) };
        return Ok((session_ctx_ty, open_call, close_call, invoke_call));
    }

    let open_ctx_arg = open_fn.sig.inputs.iter().nth(1).ok_or_else(|| {
        syn::Error::new(
            open_fn.sig.span(),
            "internal error: open_session missing context parameter",
        )
    })?;
    let ctx_ty = extract_mut_ref_type(open_ctx_arg)?;
    if close_arg_count != 1 || invoke_arg_count != 3 {
        return Err(syn::Error::new(
            open_fn.sig.span(),
            "session-context mode requires close_session(&mut T) and invoke_command(&mut T, cmd_id, params)",
        ));
    }
    let close_ctx_arg = close_fn.sig.inputs.iter().next().ok_or_else(|| {
        syn::Error::new(
            close_fn.sig.span(),
            "internal error: close_session missing context parameter",
        )
    })?;
    let close_ctx_ty = extract_mut_ref_type(close_ctx_arg)?;
    let invoke_ctx_arg = invoke_fn.sig.inputs.iter().next().ok_or_else(|| {
        syn::Error::new(
            invoke_fn.sig.span(),
            "internal error: invoke_command missing context parameter",
        )
    })?;
    let invoke_ctx_ty = extract_mut_ref_type(invoke_ctx_arg)?;
    if quote!(#ctx_ty).to_string() != quote!(#close_ctx_ty).to_string()
        || quote!(#ctx_ty).to_string() != quote!(#invoke_ctx_ty).to_string()
    {
        return Err(syn::Error::new(
            open_fn.sig.span(),
            "session context type T must be consistent across ta_open_session/ta_close_session/ta_invoke_command",
        ));
    }

    let session_ctx_ty = quote! { #ctx_ty };
    let open_call = quote! {
        let mut ctx: #ctx_ty = Default::default();
        __XteeIntoTaResult::into_ta_result(#open_ident(params, &mut ctx))?;
        Ok(ctx)
    };
    let close_call = quote! { #close_ident(ctx) };
    let invoke_call = quote! { #invoke_ident(ctx, cmd_id, params) };
    Ok((session_ctx_ty, open_call, close_call, invoke_call))
}

fn extract_mut_ref_type(arg: &FnArg) -> Result<&syn::Type, syn::Error> {
    if let FnArg::Typed(pat_ty) = arg
        && let syn::Type::Reference(type_ref) = pat_ty.ty.as_ref()
        && type_ref.mutability.is_some()
    {
        return Ok(type_ref.elem.as_ref());
    }
    Err(syn::Error::new(arg.span(), "argument must be &mut T"))
}
