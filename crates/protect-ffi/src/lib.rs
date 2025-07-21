//! FFI bindings for the CipherStash Client SDK.
//!
//! This crate provides C-compatible functions for PHP FFI integration with proper
//! error handling and memory management.
//!
//! The main entry point is the [`Client`] type, which manages encryption and decryption
//! operations. All FFI functions operate on or return a pointer to a [`Client`] instance.

use cipherstash_client::{
    config::{
        console_config::ConsoleConfig, cts_config::CtsConfig, errors::ConfigError,
        zero_kms_config::ZeroKMSConfig, EnvSource,
    },
    credentials::{ServiceCredentials, ServiceToken},
    encryption::{
        self, EncryptionError, IndexTerm, Plaintext, PlaintextTarget, ReferencedPendingPipeline,
        ScopedCipher, TypeParseError,
    },
    schema::ColumnConfig,
    zerokms::{self, EncryptedRecord, WithContext, ZeroKMSWithClientKey},
};
use encrypt_config::{CastAs, EncryptConfig, Identifier};
use libc::c_char;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::ptr;
use std::sync::Arc;
use std::{collections::HashMap, str::FromStr};
use tokio::runtime::Runtime;

mod encrypt_config;
mod plaintext_target;
mod safe_ffi;

/// Get the shared async runtime instance.
///
/// Creates a new Tokio runtime on first call within the current process and reuses it
/// for subsequent calls in the same process. Each PHP process gets its own runtime instance.
fn runtime() -> Result<&'static Runtime, Error> {
    static RUNTIME: OnceCell<Runtime> = OnceCell::new();

    RUNTIME.get_or_try_init(|| Runtime::new().map_err(|e| Error::Runtime(e.to_string())))
}

/// An encryption client that manages cipher operations and configuration.
#[derive(Clone)]
pub struct Client {
    cipher: Arc<ScopedZeroKMSNoRefresh>,
    zerokms: Arc<ZeroKMSWithClientKey<ServiceCredentials>>,
    encrypt_config: Arc<HashMap<Identifier, (ColumnConfig, CastAs)>>,
}

/// A structured text encryption vector entry.
#[derive(Debug, Deserialize, Serialize)]
pub struct SteVecEntry {
    /// Tokenized selector representing the encrypted JSON path to the value.
    #[serde(rename = "s")]
    tokenized_selector: String,
    /// Encrypted term value for equality and order-preserving queries.
    #[serde(rename = "t")]
    term: String,
    /// Base85-encoded ciphertext containing the encrypted record data.
    #[serde(rename = "r")]
    record: String,
    /// Whether the parent JSON element is an array.
    #[serde(rename = "pa")]
    parent_is_array: bool,
}

/// An encrypted value with associated encryption indexes or structured text encryption vectors.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "k")]
pub enum Encrypted {
    /// Encrypted ciphertext with encryption indexes based on column configuration.
    #[serde(rename = "ct")]
    Ciphertext {
        /// Base85-encoded ciphertext containing the encrypted data.
        #[serde(rename = "c")]
        ciphertext: String,
        /// Data type for casting.
        #[serde(rename = "dt")]
        data_type: String,
        /// HMAC index for exact equality queries and uniqueness constraints.
        #[serde(rename = "hm")]
        unique_index: Option<String>,
        /// Order-revealing encryption index for equality checks, range comparisons, range queries, and
        /// sorting operations.
        #[serde(rename = "ob")]
        ore_index: Option<Vec<String>>,
        /// Bloom filter index for full-text search queries.
        #[serde(rename = "bf")]
        match_index: Option<Vec<u16>>,
        /// Table and column identifier for this encrypted value.
        #[serde(rename = "i")]
        identifier: Identifier,
        /// Schema version for backward compatibility.
        #[serde(rename = "v")]
        version: u16,
    },
    /// Encrypted ciphertext with structured text encryption vector for JSONB containment queries.
    #[serde(rename = "sv")]
    SteVec {
        /// Base85-encoded ciphertext containing the encrypted data.
        #[serde(rename = "c")]
        ciphertext: String,
        /// Data type for casting.
        #[serde(rename = "dt")]
        data_type: String,
        /// Structured text encryption vector for JSONB containment queries.
        #[serde(rename = "sv")]
        ste_vec_index: Option<Vec<SteVecEntry>>,
        /// Table and column identifier for this encrypted value.
        #[serde(rename = "i")]
        identifier: Identifier,
        /// Schema version for backward compatibility.
        #[serde(rename = "v")]
        version: u16,
    },
}

/// Errors that can occur during encryption and decryption operations.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Configuration parsing error.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// ZeroKMS encryption/decryption error.
    #[error(transparent)]
    ZeroKMS(#[from] zerokms::Error),
    /// Encryption operation error.
    #[error(transparent)]
    Encryption(#[from] EncryptionError),
    /// Type parsing error.
    #[error(transparent)]
    TypeParse(#[from] TypeParseError),
    /// JSON parsing error.
    #[error(transparent)]
    Parse(#[from] serde_json::Error),
    /// UTF-8 string conversion error.
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    /// Unsupported schema version.
    #[error("unsupported schema version {0}: only version 2 is supported")]
    UnsupportedSchemaVersion(u32),
    /// Unknown column identifier in configuration.
    #[error("unknown column `{}.{}`", _0.table, _0.column)]
    UnknownColumn(Identifier),

    /// Base85 encoding/decoding error.
    #[error("base85 encoding error: {0}")]
    Base85(String),
    /// Feature not yet implemented.
    #[error("feature not implemented: {0}")]
    Unimplemented(String),
    /// Async runtime error.
    #[error("runtime error: {0}")]
    Runtime(String),

    /// Null pointer passed where non-null expected.
    #[error("null pointer provided")]
    NullPointer,
    /// String conversion error.
    #[error("string conversion error: {0}")]
    StringConversion(String),
    /// Internal invariant violation - indicates a bug in protect-ffi.
    #[error("internal error: {0} (this is a bug in protect-ffi, please file an issue at https://github.com/cipherstash/protectphp-ffi/issues)")]
    InvariantViolation(String),
}

type ScopedZeroKMSNoRefresh = ScopedCipher<ServiceCredentials>;

#[derive(Deserialize)]
struct ClientConfig {
    #[serde(default)]
    _dataset_id: Option<String>,
}

/// Creates a new client instance from the provided encryption configuration.
///
/// # Errors
///
/// Returns an error if the `config_json` is invalid JSON, contains unsupported
/// encryption options, or if the client cannot be initialized.
///
/// # Safety
///
/// The caller must ensure `config_json` points to a valid null-terminated C string.
/// The returned pointer must be freed using [`free_client()`].
#[no_mangle]
pub extern "C" fn new_client(
    config_json: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut Client {
    let result: Result<Box<Client>, Error> = runtime().and_then(|rt| {
        rt.block_on(async {
            let config_json = safe_ffi::c_str_to_string(config_json)?;
            let encrypt_config = EncryptConfig::from_str(&config_json)?;
            let client = new_client_inner(encrypt_config).await?;
            Ok(Box::new(client))
        })
    });

    handle_ffi_result!(result, error_out, Box::into_raw)
}

async fn new_client_inner(encrypt_config: EncryptConfig) -> Result<Client, Error> {
    let console_config = ConsoleConfig::builder().with_env().build()?;
    let cts_config = CtsConfig::builder().with_env().build()?;
    let zerokms_config = ZeroKMSConfig::builder()
        .add_source(EnvSource::default())
        .console_config(&console_config)
        .cts_config(&cts_config)
        .build_with_client_key()?;

    let zerokms = Arc::new(zerokms_config.create_client());

    let cipher = ScopedZeroKMSNoRefresh::init(zerokms.clone(), None).await?;

    Ok(Client {
        cipher: Arc::new(cipher),
        zerokms,
        encrypt_config: Arc::new(encrypt_config.into_config_map()),
    })
}

/// Encrypts plaintext for a specific table column.
///
/// Returns a JSON string containing the encrypted result and encryption indexes.
///
/// # Errors
///
/// Returns an error if the table/column is not found in the encryption configuration,
/// the encryption context JSON is malformed, or encryption fails.
///
/// # Safety
///
/// All pointer parameters must be valid null-terminated C strings.
/// The returned pointer must be freed using [`free_string()`].
#[no_mangle]
pub extern "C" fn encrypt(
    client: *const Client,
    plaintext: *const c_char,
    column: *const c_char,
    table: *const c_char,
    context_json: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut c_char {
    let result: Result<String, Error> = runtime().and_then(|rt| {
        rt.block_on(async {
            let client = safe_ffi::client_ref(client)?;
            let plaintext = safe_ffi::c_str_to_string(plaintext)?;
            let column = safe_ffi::c_str_to_string(column)?;
            let table = safe_ffi::c_str_to_string(table)?;
            let context = safe_ffi::optional_c_str_to_string(context_json)?;

            let encryption_context = if let Some(context) = context {
                parse_encryption_context(&context)?
            } else {
                Vec::new()
            };

            let identifier = Identifier::new(table, column);
            let (column_config, cast_as) = client
                .encrypt_config
                .get(&identifier)
                .ok_or_else(|| Error::UnknownColumn(identifier.clone()))?;

            let mut plaintext_target = plaintext_target::new(plaintext, column_config)?;
            plaintext_target.context = encryption_context;

            let encrypted =
                encrypt_inner(client.clone(), plaintext_target, &identifier, cast_as, None).await?;

            serde_json::to_string(&encrypted).map_err(Error::from)
        })
    });

    handle_ffi_result!(result, error_out, |json_string| {
        safe_ffi::string_to_c_string(json_string).unwrap_or(ptr::null_mut())
    })
}

async fn encrypt_inner(
    client: Client,
    plaintext_target: PlaintextTarget,
    identifier: &Identifier,
    cast_as: &CastAs,
    service_token: Option<ServiceToken>,
) -> Result<Encrypted, Error> {
    let mut pipeline = ReferencedPendingPipeline::new(client.cipher);

    pipeline.add_with_ref::<PlaintextTarget>(plaintext_target, 0)?;

    let mut source_encrypted = pipeline.encrypt(service_token).await?;

    let encrypted = source_encrypted.remove(0).ok_or_else(|| {
        Error::InvariantViolation(
            "`encrypt` expected a single result in the pipeline, but there were none".to_string(),
        )
    })?;

    to_eql_encrypted(encrypted, identifier, cast_as)
}

/// Parses JSON encryption context into ZeroKMS context objects.
fn parse_encryption_context(context_json: &str) -> Result<Vec<zerokms::Context>, Error> {
    let context: serde_json::Value = serde_json::from_str(context_json)?;
    let mut encryption_context = Vec::new();

    if let Some(identity_claim) = context.get("identity_claim") {
        if let Some(claims_array) = identity_claim.as_array() {
            for claim in claims_array {
                if let Some(claim) = claim.as_str() {
                    encryption_context.push(zerokms::Context::new_identity_claim(claim));
                }
            }
        }
    }

    if let Some(tags) = context.get("tag") {
        if let Some(tags_array) = tags.as_array() {
            for tag in tags_array {
                if let Some(tag) = tag.as_str() {
                    encryption_context.push(zerokms::Context::new_tag(tag));
                }
            }
        }
    }

    if let Some(values) = context.get("value") {
        if let Some(values_array) = values.as_array() {
            for value_pair in values_array {
                if let Some(pair_obj) = value_pair.as_object() {
                    if let (Some(key), Some(value)) = (
                        pair_obj.get("key").and_then(|k| k.as_str()),
                        pair_obj.get("value").and_then(|v| v.as_str()),
                    ) {
                        encryption_context.push(zerokms::Context::new_value(key, value));
                    }
                }
            }
        }
    }

    Ok(encryption_context)
}

/// Decrypts ciphertext with optional encryption context.
///
/// # Errors
///
/// Returns an error if the `ciphertext` is invalid, the encryption context JSON is malformed,
/// or decryption fails due to key or permission issues.
///
/// # Safety
///
/// All pointer parameters must be valid null-terminated C strings.
/// The returned pointer must be freed using [`free_string()`].
#[no_mangle]
pub extern "C" fn decrypt(
    client: *const Client,
    ciphertext: *const c_char,
    context_json: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut c_char {
    let result: Result<String, Error> = runtime().and_then(|rt| {
        rt.block_on(async {
            let client = safe_ffi::client_ref(client)?;
            let ciphertext = safe_ffi::c_str_to_string(ciphertext)?;
            let context = safe_ffi::optional_c_str_to_string(context_json)?;

            let encryption_context = if let Some(context) = context {
                parse_encryption_context(&context)?
            } else {
                Vec::new()
            };

            let plaintext =
                decrypt_inner(client.clone(), ciphertext, encryption_context, None).await?;
            Ok(plaintext)
        })
    });

    handle_ffi_result!(result, error_out, |plaintext| {
        safe_ffi::string_to_c_string(plaintext).unwrap_or(ptr::null_mut())
    })
}

async fn decrypt_inner(
    client: Client,
    ciphertext: String,
    encryption_context: Vec<zerokms::Context>,
    service_token: Option<ServiceToken>,
) -> Result<String, Error> {
    let encrypted_record = encrypted_record_from_mp_base85(&ciphertext, encryption_context)?;

    let decrypted = client
        .zerokms
        .decrypt_single(encrypted_record, service_token)
        .await?;

    plaintext_from_bytes(decrypted)
}

fn encrypted_record_from_mp_base85(
    base85str: &str,
    encryption_context: Vec<zerokms::Context>,
) -> Result<WithContext, Error> {
    let encrypted_record = EncryptedRecord::from_mp_base85(base85str)
        // The error type from `to_mp_base85` isn't public, so we don't derive an error for this one.
        // Instead, we use `map_err`.
        .map_err(|err| Error::Base85(err.to_string()))?;

    Ok(WithContext {
        record: encrypted_record,
        context: encryption_context,
    })
}

fn plaintext_from_bytes(bytes: Vec<u8>) -> Result<String, Error> {
    let plaintext = Plaintext::from_slice(bytes.as_slice())?;

    match plaintext {
        Plaintext::Utf8Str(Some(ref inner)) => Ok(inner.clone()),
        Plaintext::JsonB(Some(ref json_value)) => {
            serde_json::to_string(json_value).map_err(Error::from)
        }
        _ => Err(Error::Unimplemented(format!(
            "plaintext decryption for type `{:?}`",
            plaintext
        ))),
    }
}

fn to_eql_encrypted(
    encrypted: encryption::Encrypted,
    identifier: &Identifier,
    cast_as: &CastAs,
) -> Result<Encrypted, Error> {
    match (cast_as, encrypted) {
        // JSONB always uses SteVec format
        (CastAs::JsonB, encrypted) => {
            let (ciphertext, ste_vec_index) = match encrypted {
                encryption::Encrypted::SteVec(ste_vec_index) => {
                    let root_ciphertext = ste_vec_index.root_ciphertext().map_err(|e| {
                        Error::InvariantViolation(format!("failed to get root ciphertext: {}", e))
                    })?;

                    let ciphertext = root_ciphertext
                        .to_mp_base85()
                        // The error type from `to_mp_base85` isn't public, so we don't derive an error for this one.
                        // Instead, we use `map_err`.
                        .map_err(|err| Error::Base85(err.to_string()))?;

                    let ste_vec_entries: Result<Vec<SteVecEntry>, Error> = ste_vec_index
                        .into_iter()
                        .map(|entry| {
                            let record = entry
                                .record
                                .to_mp_base85()
                                // The error type from `to_mp_base85` isn't public, so we don't derive an error for this one.
                                // Instead, we use `map_err`.
                                .map_err(|err| Error::Base85(err.to_string()))?;

                            Ok(SteVecEntry {
                                tokenized_selector: hex::encode(
                                    entry.tokenized_selector.as_bytes(),
                                ),
                                term: hex::encode(
                                    &serde_json::to_vec(&entry.term).map_err(Error::Parse)?,
                                ),
                                record,
                                parent_is_array: entry.parent_is_array,
                            })
                        })
                        .collect();

                    (ciphertext, Some(ste_vec_entries?))
                }
                encryption::Encrypted::Record(ciphertext, _terms) => {
                    let ciphertext = ciphertext
                        .to_mp_base85()
                        // The error type from `to_mp_base85` isn't public, so we don't derive an error for this one.
                        // Instead, we use `map_err`.
                        .map_err(|err| Error::Base85(err.to_string()))?;

                    (ciphertext, None)
                }
            };

            Ok(Encrypted::SteVec {
                ciphertext,
                data_type: cast_as.to_string(),
                ste_vec_index,
                identifier: identifier.to_owned(),
                version: 2,
            })
        }

        // Non-JSONB types with indexes
        (_, encryption::Encrypted::Record(ciphertext, terms)) => {
            let ciphertext = ciphertext
                .to_mp_base85()
                // The error type from `to_mp_base85` isn't public, so we don't derive an error for this one.
                // Instead, we use `map_err`.
                .map_err(|err| Error::Base85(err.to_string()))?;

            let mut unique_index = None;
            let mut ore_index = None;
            let mut match_index = None;

            for index_term in terms {
                match index_term {
                    IndexTerm::Binary(bytes) => {
                        unique_index = Some(format_index_term_binary(&bytes))
                    }
                    IndexTerm::BitMap(inner) => match_index = Some(inner),
                    IndexTerm::OreArray(vec_of_bytes) => {
                        ore_index = Some(format_index_term_ore_array(&vec_of_bytes));
                    }
                    IndexTerm::OreFull(bytes) => {
                        ore_index = Some(format_index_term_ore(&bytes));
                    }
                    IndexTerm::OreLeft(bytes) => {
                        ore_index = Some(format_index_term_ore(&bytes));
                    }
                    IndexTerm::Null => {}
                    term => return Err(Error::Unimplemented(format!("index term `{term:?}`"))),
                };
            }

            Ok(Encrypted::Ciphertext {
                ciphertext,
                data_type: cast_as.to_string(),
                unique_index,
                ore_index,
                match_index,
                identifier: identifier.to_owned(),
                version: 2,
            })
        }

        // Non-JSONB types should never return SteVec
        (_, encryption::Encrypted::SteVec(_)) => Err(Error::InvariantViolation(
            "non-JSONB type returned SteVec from encryption library".to_string(),
        )),
    }
}

/// Formats HMAC index bytes into hex-encoded string.
fn format_index_term_binary(index_bytes: &[u8]) -> String {
    hex::encode(index_bytes)
}

/// Formats ORE index bytes into hex-encoded string.
fn format_index_term_ore_bytes(index_bytes: &[u8]) -> String {
    hex::encode(index_bytes)
}

/// Formats ORE index array bytes into hex-encoded strings.
fn format_index_term_ore_array(ore_byte_arrays: &[Vec<u8>]) -> Vec<String> {
    ore_byte_arrays
        .iter()
        .map(|index_bytes| format_index_term_ore_bytes(index_bytes))
        .collect()
}

/// Formats ORE index bytes into a single-element hex-encoded string array.
fn format_index_term_ore(index_bytes: &[u8]) -> Vec<String> {
    vec![format_index_term_ore_bytes(index_bytes)]
}

/// Bulk encryption request item containing plaintext data and metadata.
#[derive(Deserialize)]
struct BulkEncryptItem {
    /// The plaintext data to encrypt.
    plaintext: String,
    /// The target column name.
    column: String,
    /// The target table name.
    table: String,
    /// Optional encryption context (defaults to empty if not provided).
    #[serde(default)]
    context: Option<serde_json::Value>,
}

/// Bulk decryption request item containing ciphertext and optional context.
#[derive(Deserialize)]
struct BulkDecryptItem {
    /// The ciphertext to decrypt.
    ciphertext: String,
    /// Optional encryption context (defaults to empty if not provided).
    #[serde(default)]
    context: Option<serde_json::Value>,
}

/// Search term creation request item containing plaintext and target metadata.
#[derive(Deserialize)]
struct SearchTermItem {
    /// The plaintext data to create search terms for.
    plaintext: String,
    /// The target column name.
    column: String,
    /// The target table name.
    table: String,
    /// Optional encryption context (defaults to empty if not provided).
    #[serde(default)]
    context: Option<serde_json::Value>,
}

/// Encrypts multiple plaintext items in bulk.
///
/// # Errors
///
/// Returns an error if the JSON input is malformed, contains unknown column/table
/// combinations, has invalid encryption context, or if encryption fails.
///
/// # Safety
///
/// All pointer parameters must be valid null-terminated C strings.
/// The returned pointer must be freed using [`free_string()`].
#[no_mangle]
pub extern "C" fn encrypt_bulk(
    client: *const Client,
    items_json: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut c_char {
    let result: Result<String, Error> = runtime().and_then(|rt| {
        rt.block_on(async {
            let client = safe_ffi::client_ref(client)?;
            let items_json_string = safe_ffi::c_str_to_string(items_json)?;
            let items: Vec<BulkEncryptItem> = serde_json::from_str(&items_json_string)?;

            let mut plaintext_targets = Vec::new();

            for item in items {
                let encryption_context = if let Some(context_value) = item.context {
                    let context_json = serde_json::to_string(&context_value)?;
                    parse_encryption_context(&context_json)?
                } else {
                    Vec::new()
                };

                let identifier = Identifier::new(item.table, item.column);
                let (column_config, cast_as) = client
                    .encrypt_config
                    .get(&identifier)
                    .ok_or_else(|| Error::UnknownColumn(identifier.clone()))?;

                let mut plaintext_target = plaintext_target::new(item.plaintext, column_config)?;
                plaintext_target.context = encryption_context;

                plaintext_targets.push((plaintext_target, identifier, *cast_as));
            }

            let encrypted_results =
                encrypt_bulk_inner(client.clone(), plaintext_targets, None).await?;
            serde_json::to_string(&encrypted_results).map_err(Error::from)
        })
    });

    handle_ffi_result!(result, error_out, |json_string| {
        safe_ffi::string_to_c_string(json_string).unwrap_or(ptr::null_mut())
    })
}

async fn encrypt_bulk_inner(
    client: Client,
    plaintext_targets: Vec<(PlaintextTarget, Identifier, CastAs)>,
    service_token: Option<ServiceToken>,
) -> Result<Vec<Encrypted>, Error> {
    let len = plaintext_targets.len();
    let mut pipeline = ReferencedPendingPipeline::new(client.cipher);
    let (plaintext_targets, identifiers, cast_types): (
        Vec<PlaintextTarget>,
        Vec<Identifier>,
        Vec<CastAs>,
    ) = plaintext_targets.into_iter().fold(
        (Vec::new(), Vec::new(), Vec::new()),
        |(mut plaintext_targets, mut identifiers, mut cast_types),
         (plaintext_target, identifier, cast_type)| {
            plaintext_targets.push(plaintext_target);
            identifiers.push(identifier);
            cast_types.push(cast_type);
            (plaintext_targets, identifiers, cast_types)
        },
    );

    for (index, plaintext_target) in plaintext_targets.into_iter().enumerate() {
        pipeline.add_with_ref::<PlaintextTarget>(plaintext_target, index)?;
    }

    let mut source_encrypted = pipeline.encrypt(service_token).await?;

    let mut results: Vec<Encrypted> = Vec::with_capacity(len);

    for index in 0..len {
        let encrypted = source_encrypted.remove(index).ok_or_else(|| {
            Error::InvariantViolation(format!(
                "`encrypt_bulk` expected a result in the pipeline at index {index}, but there was none"
            ))
        })?;

        let identifier = &identifiers[index];
        let cast_as = &cast_types[index];

        let eql_payload = to_eql_encrypted(encrypted, identifier, cast_as)?;

        results.push(eql_payload);
    }

    Ok(results)
}

/// Decrypts multiple ciphertext items in bulk.
///
/// # Errors
///
/// Returns an error if the JSON input is malformed, contains invalid `ciphertext`,
/// has malformed encryption context, or if decryption fails.
///
/// # Safety
///
/// All pointer parameters must be valid null-terminated C strings.
/// The returned pointer must be freed using [`free_string()`].
#[no_mangle]
pub extern "C" fn decrypt_bulk(
    client: *const Client,
    items_json: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut c_char {
    let result: Result<String, Error> = runtime().and_then(|rt| {
        rt.block_on(async {
            let client = safe_ffi::client_ref(client)?;
            let items_json_string = safe_ffi::c_str_to_string(items_json)?;
            let items: Vec<BulkDecryptItem> = serde_json::from_str(&items_json_string)?;

            let mut ciphertexts = Vec::new();

            for item in items {
                let encryption_context = if let Some(context_value) = item.context {
                    let context_json = serde_json::to_string(&context_value)?;
                    parse_encryption_context(&context_json)?
                } else {
                    Vec::new()
                };

                ciphertexts.push((item.ciphertext, encryption_context));
            }

            let plaintexts = decrypt_bulk_inner(client.clone(), ciphertexts, None).await?;
            serde_json::to_string(&plaintexts).map_err(Error::from)
        })
    });

    handle_ffi_result!(result, error_out, |json_string| {
        safe_ffi::string_to_c_string(json_string).unwrap_or(ptr::null_mut())
    })
}

async fn decrypt_bulk_inner(
    client: Client,
    ciphertexts: Vec<(String, Vec<zerokms::Context>)>,
    service_token: Option<ServiceToken>,
) -> Result<Vec<String>, Error> {
    let len = ciphertexts.len();
    let mut encrypted_records: Vec<WithContext> = Vec::with_capacity(ciphertexts.len());

    for (ciphertext, encryption_context) in ciphertexts {
        let encrypted_record = encrypted_record_from_mp_base85(&ciphertext, encryption_context)?;
        encrypted_records.push(encrypted_record);
    }

    let decrypted = client
        .zerokms
        .decrypt(encrypted_records, service_token)
        .await?;

    let mut plaintexts: Vec<String> = Vec::with_capacity(len);

    for item in decrypted {
        plaintexts.push(plaintext_from_bytes(item)?);
    }

    Ok(plaintexts)
}

/// Creates encrypted search terms for querying encrypted data.
///
/// Returns a JSON array of encrypted search terms that can be used in database queries.
/// Each search term contains the encryption indexes (`unique`, `ore`, `match`, `ste_vec`)
/// but not the full ciphertext.
///
/// # Errors
///
/// Returns an error if the JSON input is malformed, contains unknown column/table
/// combinations, has invalid encryption context, or if encryption fails.
///
/// # Safety
///
/// All pointer parameters must be valid null-terminated C strings.
/// The returned pointer must be freed using [`free_string()`].
#[no_mangle]
pub extern "C" fn create_search_terms(
    client: *const Client,
    terms_json: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut c_char {
    let result: Result<String, Error> = runtime().and_then(|rt| {
        rt.block_on(async {
            let client = safe_ffi::client_ref(client)?;
            let terms_json = safe_ffi::c_str_to_string(terms_json)?;
            let terms: Vec<SearchTermItem> = serde_json::from_str(&terms_json)?;

            let mut search_terms_json = Vec::new();

            for term in terms {
                let encryption_context = if let Some(context_value) = term.context {
                    let context_json = serde_json::to_string(&context_value)?;
                    parse_encryption_context(&context_json)?
                } else {
                    Vec::new()
                };

                let identifier = Identifier::new(term.table, term.column);
                let (column_config, cast_as) = client
                    .encrypt_config
                    .get(&identifier)
                    .ok_or_else(|| Error::UnknownColumn(identifier.clone()))?;

                let mut plaintext_target = plaintext_target::new(term.plaintext, column_config)?;
                plaintext_target.context = encryption_context;

                let encrypted =
                    encrypt_inner(client.clone(), plaintext_target, &identifier, cast_as, None)
                        .await?;

                let search_term_json = match encrypted {
                    Encrypted::Ciphertext {
                        unique_index,
                        ore_index,
                        match_index,
                        identifier,
                        ..
                    } => {
                        let hm_json = serde_json::to_string(&unique_index)?;
                        let ob_json = serde_json::to_string(&ore_index)?;
                        let bf_json = serde_json::to_string(&match_index)?;
                        let i_json = format!(
                            r#"{{"t":"{}","c":"{}"}}"#,
                            identifier.table, identifier.column
                        );

                        format!(
                            r#"{{"hm":{},"ob":{},"bf":{},"i":{}}}"#,
                            hm_json, ob_json, bf_json, i_json
                        )
                    }
                    Encrypted::SteVec {
                        ste_vec_index,
                        identifier,
                        ..
                    } => {
                        let sv_json = serde_json::to_string(&ste_vec_index)?;
                        let i_json = format!(
                            r#"{{"t":"{}","c":"{}"}}"#,
                            identifier.table, identifier.column
                        );

                        format!(r#"{{"sv":{},"i":{}}}"#, sv_json, i_json)
                    }
                };

                search_terms_json.push(search_term_json);
            }

            let result = format!("[{}]", search_terms_json.join(","));
            Ok(result)
        })
    });

    handle_ffi_result!(result, error_out, |json_string| {
        safe_ffi::string_to_c_string(json_string).unwrap_or(ptr::null_mut())
    })
}

/// Frees a client instance and its associated resources.
///
/// # Safety
///
/// The `client` pointer must have been returned by [`new_client()`] and not previously freed.
#[no_mangle]
pub extern "C" fn free_client(client: *mut Client) {
    safe_ffi::free_boxed_client(client);
}

/// Frees a C string allocated by this library.
///
/// # Safety
///
/// The `string` pointer must have been returned by this library and not previously freed.
#[no_mangle]
pub extern "C" fn free_string(string: *mut c_char) {
    safe_ffi::free_c_string(string);
}

#[cfg(test)]
mod lib {
    mod tests {
        use crate::*;
        use std::ffi::{CStr, CString};
        use std::ptr;

        const TEST_TABLE: &str = "users";
        const TEST_COLUMN: &str = "email";
        const TEST_EMAIL: &str = "john@example.com";
        const TEST_CIPHERTEXT: &str = "9jqo^BlbD-BleB1djH3bb1ULW4j$";
        const TEST_DATA_TYPE: &str = "text";
        const TEST_SCHEMA_VERSION: u16 = 2;

        /// Create a sample ciphertext `Encrypted` variant for testing.
        fn create_encrypted_ciphertext(
            table: &str,
            column: &str,
            ciphertext: &str,
            data_type: &str,
        ) -> Encrypted {
            Encrypted::Ciphertext {
                ciphertext: ciphertext.to_string(),
                data_type: data_type.to_string(),
                unique_index: None,
                ore_index: None,
                match_index: None,
                identifier: Identifier {
                    table: table.to_string(),
                    column: column.to_string(),
                },
                version: TEST_SCHEMA_VERSION,
            }
        }

        /// Create a sample SteVec `Encrypted` variant for testing.
        fn create_encrypted_ste_vec(
            table: &str,
            column: &str,
            ciphertext: &str,
            data_type: &str,
            ste_vec_entries: Option<Vec<SteVecEntry>>,
        ) -> Encrypted {
            Encrypted::SteVec {
                ciphertext: ciphertext.to_string(),
                data_type: data_type.to_string(),
                ste_vec_index: ste_vec_entries,
                identifier: Identifier {
                    table: table.to_string(),
                    column: column.to_string(),
                },
                version: TEST_SCHEMA_VERSION,
            }
        }

        /// Assert that a null pointer error is returned as a valid C string.
        fn assert_null_pointer_error(error_ptr: *mut c_char) {
            assert!(!error_ptr.is_null());
            let error_c_str = unsafe { CStr::from_ptr(error_ptr) };
            assert!(error_c_str.to_str().is_ok());
            free_string(error_ptr);
        }

        #[test]
        fn test_runtime_creation() {
            let first_runtime = runtime();
            assert!(first_runtime.is_ok());

            let second_runtime = runtime();
            assert!(second_runtime.is_ok());

            assert!(std::ptr::eq(
                first_runtime.unwrap(),
                second_runtime.unwrap()
            ));
        }

        #[test]
        fn test_encrypted_ciphertext_json_format() {
            let sample_encrypted = create_encrypted_ciphertext(
                TEST_TABLE,
                TEST_COLUMN,
                TEST_CIPHERTEXT,
                TEST_DATA_TYPE,
            );

            let json_string = serde_json::to_string(&sample_encrypted).unwrap();
            let parsed_json: serde_json::Value = serde_json::from_str(&json_string).unwrap();

            assert_eq!(parsed_json["k"], "ct");
            assert_eq!(parsed_json["c"], TEST_CIPHERTEXT);
            assert_eq!(parsed_json["dt"], TEST_DATA_TYPE);
            assert_eq!(parsed_json["hm"], serde_json::Value::Null);
            assert_eq!(parsed_json["ob"], serde_json::Value::Null);
            assert_eq!(parsed_json["bf"], serde_json::Value::Null);
            assert_eq!(parsed_json["v"], TEST_SCHEMA_VERSION);

            let identifier_json = &parsed_json["i"];
            assert_eq!(identifier_json["t"], TEST_TABLE);
            assert_eq!(identifier_json["c"], TEST_COLUMN);
        }

        #[test]
        fn test_encrypted_ste_vec_json_format_with_null_entries() {
            let sample_encrypted =
                create_encrypted_ste_vec(TEST_TABLE, TEST_COLUMN, TEST_CIPHERTEXT, "jsonb", None);

            let json_string = serde_json::to_string(&sample_encrypted).unwrap();
            let parsed_json: serde_json::Value = serde_json::from_str(&json_string).unwrap();

            assert_eq!(parsed_json["k"], "sv");
            assert_eq!(parsed_json["sv"], serde_json::Value::Null);
        }

        #[test]
        fn test_new_client_null_config() {
            let mut error_ptr: *mut c_char = ptr::null_mut();
            let error_out = &mut error_ptr as *mut *mut c_char;

            let client_result = new_client(ptr::null(), error_out);

            assert!(client_result.is_null());
            assert_null_pointer_error(error_ptr);
        }

        #[test]
        fn test_encrypt_null_client() {
            let mut error_ptr: *mut c_char = ptr::null_mut();
            let error_out = &mut error_ptr as *mut *mut c_char;

            let table = CString::new(TEST_TABLE).unwrap();
            let column = CString::new(TEST_COLUMN).unwrap();
            let plaintext = CString::new(TEST_EMAIL).unwrap();

            let encrypt_result = encrypt(
                ptr::null(),
                plaintext.as_ptr(),
                column.as_ptr(),
                table.as_ptr(),
                ptr::null(),
                error_out,
            );

            assert!(encrypt_result.is_null());
            assert_null_pointer_error(error_ptr);
        }

        #[test]
        fn test_decrypt_null_client() {
            let mut error_ptr: *mut c_char = ptr::null_mut();
            let error_out = &mut error_ptr as *mut *mut c_char;

            let ciphertext = CString::new(TEST_CIPHERTEXT).unwrap();

            let decrypt_result = decrypt(ptr::null(), ciphertext.as_ptr(), ptr::null(), error_out);

            assert!(decrypt_result.is_null());
            assert_null_pointer_error(error_ptr);
        }

        #[test]
        fn test_free_functions_with_null() {
            free_client(ptr::null_mut());
            free_string(ptr::null_mut());
        }

        #[test]
        fn test_error_display() {
            let identifier = Identifier {
                table: TEST_TABLE.to_string(),
                column: TEST_COLUMN.to_string(),
            };
            let invalid_utf8_bytes = vec![0xFF, 0xFE];
            let utf8_error = std::str::from_utf8(&invalid_utf8_bytes).unwrap_err();
            let json_error = serde_json::from_str::<serde_json::Value>("{invalid}").unwrap_err();

            let test_errors = [
                // Test error display formatting for all constructible variants
                Error::Parse(json_error),
                Error::Utf8(utf8_error),
                Error::UnsupportedSchemaVersion(1),
                Error::UnknownColumn(identifier),
                Error::Base85("invalid character".to_string()),
                Error::Unimplemented("bulk operations".to_string()),
                Error::Runtime("tokio runtime failed".to_string()),
                Error::NullPointer,
                Error::StringConversion("invalid encoding".to_string()),
                Error::InvariantViolation("cipher state corrupted".to_string()),
            ];

            for error in test_errors {
                let error_message = format!("{}", error);
                assert!(!error_message.is_empty());
            }
        }

        #[test]
        fn test_error_from_conversions() {
            #[allow(invalid_from_utf8)]
            let utf8_conversion_error = std::str::from_utf8(&[0xFF, 0xFE]).unwrap_err();
            let converted_error: Error = utf8_conversion_error.into();
            assert!(matches!(converted_error, Error::Utf8(_)));

            let json_parse_error =
                serde_json::from_str::<serde_json::Value>("{invalid: json}").unwrap_err();
            let converted_error: Error = json_parse_error.into();
            assert!(matches!(converted_error, Error::Parse(_)));
        }
    }
}
