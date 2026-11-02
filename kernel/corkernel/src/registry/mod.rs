//! Windows NT Registry Architecture for CorOS.
//! 100% in-house implementation supporting standard Windows registry hives,
//! typed value cells, binary serialization, HBIN cell heap allocator,
//! regf binary parser, and transactional ACID registry operations (TxR).

pub mod hive;
pub mod reg_cell;
pub mod reg_parser;
pub mod reg_transaction;

pub use hive::{
    RegistryDatabase, RegistryKey, RegistryValue,
    REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_QWORD, REG_MULTI_SZ,
};
pub use reg_cell::{HiveBin, HbinHeader, RegistryCell, HBIN_MAGIC, HBIN_BLOCK_SIZE};
pub use reg_parser::{RegfHiveParser, RegfBaseBlock, ParsedRegKey, ParsedRegValue, REGF_MAGIC};
pub use reg_transaction::{RegistryTransactionManager, RegistryTransaction, TxLogRecord, TransactionState};
