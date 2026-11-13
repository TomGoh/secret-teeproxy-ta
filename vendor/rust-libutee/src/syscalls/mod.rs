mod arch;
pub mod macros;
// Testable wrapper seam over the macro-generated inter-TA syscall entries;
// crate-internal so the public ABI surface is unchanged.
pub(crate) mod seam;
pub mod syscall_table;
