fn main() {
    #[cfg(feature = "tee")]
    {
        let config = xtee_utee_build::TaConfig::new_default_with_cargo_env(
            "c86d23b9-e568-509e-a9b2-0ad40668caf5",
        )
        .expect("valid build-time TA UUID")
        .ta_flags(0x1c)
        .ta_stack_size(256 * 1024)
        .ta_data_size(128 * 1024 * 1024)
        .emit_main_entry(false);
        xtee_utee_build::build(config).expect("generate TA header");
    }
}
