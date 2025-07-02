//! Encryption configuration parsing and conversion for CipherStash column configurations.

use cipherstash_client::schema::{
    column::{Index, IndexType, TokenFilter, Tokenizer},
    ColumnConfig, ColumnType,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, str::FromStr};
use strum::Display;

/// Supported schema versions.
const SUPPORTED_SCHEMA_VERSIONS: &[u32] = &[2];

/// Table and column identifier for encryption configuration lookup.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Identifier {
    /// The table name.
    #[serde(rename = "t")]
    pub table: String,
    /// The column name.
    #[serde(rename = "c")]
    pub column: String,
}

impl Identifier {
    /// Create a new table and column identifier.
    pub fn new<S>(table: S, column: S) -> Self
    where
        S: Into<String>,
    {
        let table = table.into();
        let column = column.into();

        Self { table, column }
    }
}

/// Collection of table configurations indexed by table name.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Tables(HashMap<String, Table>);

impl IntoIterator for Tables {
    type Item = (String, Table);
    type IntoIter = std::collections::hash_map::IntoIter<String, Table>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Table configuration containing column definitions indexed by column name.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Table(HashMap<String, Column>);

impl IntoIterator for Table {
    type Item = (String, Column);
    type IntoIter = std::collections::hash_map::IntoIter<String, Column>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Root encryption configuration structure parsed from JSON.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct EncryptConfig {
    /// The schema version.
    #[serde(rename = "v")]
    pub version: u32,
    /// The set of table configurations.
    pub tables: Tables,
}

/// Column configuration with casting and encryption indexes.
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
pub struct Column {
    /// Data type casting for this column.
    #[serde(default)]
    cast_as: CastAs,
    /// Collection of encryption indexes for this column.
    #[serde(default)]
    indexes: Indexes,
}

/// Data type casting options for encrypted columns.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum CastAs {
    /// Treat as UTF-8 text (default).
    #[default]
    Text,
    /// Treat as a boolean value.
    Boolean,
    /// Treat as a 16-bit integer.
    SmallInt,
    /// Treat as a 32-bit integer.
    Int,
    /// Treat as a 64-bit integer.
    BigInt,
    /// Treat as a single-precision float.
    Real,
    /// Treat as a double-precision float.
    Double,
    /// Treat as a date.
    Date,
    /// Treat as a JSONB value.
    #[serde(rename = "jsonb")]
    #[strum(serialize = "jsonb")]
    JsonB,
}

/// Collection of indexes for searchable encryption and uniqueness constraints.
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq)]
pub struct Indexes {
    /// Unique index for exact equality queries and enforcing database uniqueness constraints.
    #[serde(rename = "unique")]
    unique_index: Option<UniqueIndexOpts>,
    /// Order-revealing encryption index for equality checks, range comparisons, range queries,
    /// and sorting operations.
    #[serde(rename = "ore")]
    ore_index: Option<OreIndexOpts>,
    /// Full-text search index using bloom filters for probabilistic text matching.
    #[serde(rename = "match")]
    match_index: Option<MatchIndexOpts>,
    /// Structured text encryption vector index for JSONB containment queries.
    #[serde(rename = "ste_vec")]
    ste_vec_index: Option<SteVecIndexOpts>,
}

/// Configuration options for order-revealing encryption indexes.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct OreIndexOpts {}

/// Configuration options for full-text search indexes using bloom filters.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct MatchIndexOpts {
    /// The tokenizer to use for splitting text.
    #[serde(default = "default_tokenizer")]
    tokenizer: Tokenizer,
    /// Token filters to apply to tokens.
    #[serde(default)]
    token_filters: Vec<TokenFilter>,
    /// Number of hash functions for the bloom filter.
    #[serde(default = "default_k")]
    k: usize,
    /// Bloom filter size in bits.
    #[serde(default = "default_m")]
    m: usize,
    /// Whether to include the original value in the index.
    #[serde(default)]
    include_original: bool,
}

/// Configuration options for structured text encryption vectors.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct SteVecIndexOpts {
    /// The prefix for the structured text encryption vector.
    prefix: String,
}

/// Default tokenizer for match indexes.
fn default_tokenizer() -> Tokenizer {
    Tokenizer::Standard
}

/// Default hash function count for bloom filters.
fn default_k() -> usize {
    6
}

/// Default bloom filter size in bits.
fn default_m() -> usize {
    2048
}

/// Configuration options for HMAC unique indexes that enable exact equality queries and
/// database uniqueness constraints.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct UniqueIndexOpts {
    /// Token filters to apply to unique index tokens.
    #[serde(default)]
    token_filters: Vec<TokenFilter>,
}

impl From<CastAs> for ColumnType {
    fn from(value: CastAs) -> Self {
        match value {
            CastAs::Text => ColumnType::Utf8Str,
            CastAs::Boolean => ColumnType::Boolean,
            CastAs::SmallInt => ColumnType::SmallInt,
            CastAs::Int => ColumnType::Int,
            CastAs::BigInt => ColumnType::BigInt,
            CastAs::Real | CastAs::Double => ColumnType::Float,
            CastAs::Date => ColumnType::Date,
            CastAs::JsonB => ColumnType::JsonB,
        }
    }
}

impl FromStr for EncryptConfig {
    type Err = crate::Error;

    fn from_str(data: &str) -> Result<Self, Self::Err> {
        let config: EncryptConfig = serde_json::from_str(data).map_err(crate::Error::Parse)?;

        if !SUPPORTED_SCHEMA_VERSIONS.contains(&config.version) {
            return Err(crate::Error::UnsupportedSchemaVersion(config.version));
        }

        Ok(config)
    }
}

impl EncryptConfig {
    /// Convert the encryption configuration into a [`HashMap`] mapping [`Identifier`] to
    /// [`ColumnConfig`] for fast column lookups.
    pub fn into_config_map(self) -> HashMap<Identifier, (ColumnConfig, CastAs)> {
        let mut map = HashMap::new();
        for (table_name, columns) in self.tables.into_iter() {
            for (column_name, column) in columns.into_iter() {
                let column_config = column.clone().into_column_config(&column_name);
                let key = Identifier::new(&table_name, &column_name);
                map.insert(key, (column_config, column.cast_as));
            }
        }
        map
    }
}

impl Column {
    /// Convert this column configuration into a [`ColumnConfig`].
    pub fn into_column_config(self, name: &String) -> ColumnConfig {
        let mut config = ColumnConfig::build(name.to_string()).casts_as(self.cast_as.into());

        if let Some(opts) = self.indexes.unique_index {
            config = config.add_index(Index::new(IndexType::Unique {
                token_filters: opts.token_filters,
            }))
        }

        if self.indexes.ore_index.is_some() {
            config = config.add_index(Index::new_ore());
        }

        if let Some(opts) = self.indexes.match_index {
            config = config.add_index(Index::new(IndexType::Match {
                tokenizer: opts.tokenizer,
                token_filters: opts.token_filters,
                k: opts.k,
                m: opts.m,
                include_original: opts.include_original,
            }));
        }

        if let Some(SteVecIndexOpts { prefix }) = self.indexes.ste_vec_index {
            config = config.add_index(Index::new(IndexType::SteVec { prefix }))
        }

        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(json: serde_json::Value) -> HashMap<Identifier, (ColumnConfig, CastAs)> {
        serde_json::from_value::<EncryptConfig>(json)
            .map(|config| config.into_config_map())
            .unwrap()
    }

    #[test]
    fn test_cast_as_string_representation() {
        let test_cases = [
            (CastAs::Text, "text"),
            (CastAs::Boolean, "boolean"),
            (CastAs::SmallInt, "small_int"),
            (CastAs::Int, "int"),
            (CastAs::BigInt, "big_int"),
            (CastAs::Real, "real"),
            (CastAs::Double, "double"),
            (CastAs::Date, "date"),
            (CastAs::JsonB, "jsonb"),
        ];

        for (cast_as, expected_string) in test_cases {
            assert_eq!(cast_as.to_string(), expected_string);
        }
    }

    #[test]
    fn test_basic_config_parsing() {
        let json = json!({
            "v": 2,
            "tables": {
                "users": {
                    "email": {
                        "cast_as": "text"
                    }
                }
            }
        });

        let encrypt_config = parse(json);
        let ident = Identifier::new("users", "email");
        let (column, cast_as) = encrypt_config.get(&ident).expect("column exists");

        assert_eq!(column.cast_type, ColumnType::Utf8Str);
        assert_eq!(column.name, "email");
        assert_eq!(*cast_as, CastAs::Text);
    }

    #[test]
    fn test_unique_index() {
        let json = json!({
            "v": 2,
            "tables": {
                "users": {
                    "email": {
                        "cast_as": "text",
                        "indexes": {
                            "unique": {}
                        }
                    }
                }
            }
        });

        let encrypt_config = parse(json);
        let ident = Identifier::new("users", "email");
        let (column, cast_as) = encrypt_config.get(&ident).expect("column exists");

        assert_eq!(
            column.indexes[0].index_type,
            IndexType::Unique {
                token_filters: vec![]
            }
        );

        assert_eq!(*cast_as, CastAs::Text);
    }

    #[test]
    fn test_unique_index_with_token_filters() {
        let json = json!({
            "v": 2,
            "tables": {
                "users": {
                    "username": {
                        "cast_as": "text",
                        "indexes": {
                            "unique": {
                                "token_filters": [
                                    {
                                        "kind": "downcase"
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        });

        let encrypt_config = parse(json);
        let ident = Identifier::new("users", "username");
        let (column, cast_as) = encrypt_config.get(&ident).expect("column exists");

        assert_eq!(
            column.indexes[0].index_type,
            IndexType::Unique {
                token_filters: vec![TokenFilter::Downcase]
            }
        );

        assert_eq!(*cast_as, CastAs::Text);
    }

    #[test]
    fn test_ore_index() {
        let json = json!({
            "v": 2,
            "tables": {
                "users": {
                    "age": {
                        "cast_as": "int",
                        "indexes": {
                            "ore": {}
                        }
                    }
                }
            }
        });

        let encrypt_config = parse(json);
        let ident = Identifier::new("users", "age");
        let (column, cast_as) = encrypt_config.get(&ident).expect("column exists");

        assert_eq!(column.indexes[0].index_type, IndexType::Ore);
        assert_eq!(*cast_as, CastAs::Int);
    }

    #[test]
    fn test_match_index_defaults() {
        let json = json!({
            "v": 2,
            "tables": {
                "users": {
                    "notes": {
                        "cast_as": "text",
                        "indexes": {
                            "match": {}
                        }
                    }
                }
            }
        });

        let encrypt_config = parse(json);
        let ident = Identifier::new("users", "notes");
        let (column, cast_as) = encrypt_config.get(&ident).expect("column exists");

        assert_eq!(
            column.indexes[0].index_type,
            IndexType::Match {
                tokenizer: Tokenizer::Standard,
                token_filters: vec![],
                k: 6,
                m: 2048,
                include_original: false
            }
        );

        assert_eq!(*cast_as, CastAs::Text);
    }

    #[test]
    fn test_match_index_custom_options() {
        let json = json!({
            "v": 2,
            "tables": {
                "users": {
                    "description": {
                        "cast_as": "text",
                        "indexes": {
                            "match": {
                                "tokenizer": {
                                    "kind": "ngram",
                                    "token_length": 3,
                                },
                                "token_filters": [
                                    {
                                        "kind": "downcase"
                                    }
                                ],
                                "k": 8,
                                "m": 1024,
                                "include_original": true
                            }
                        }
                    }
                }
            }
        });

        let encrypt_config = parse(json);
        let ident = Identifier::new("users", "description");
        let (column, cast_as) = encrypt_config.get(&ident).expect("column exists");

        assert_eq!(
            column.indexes[0].index_type,
            IndexType::Match {
                tokenizer: Tokenizer::Ngram { token_length: 3 },
                token_filters: vec![TokenFilter::Downcase],
                k: 8,
                m: 1024,
                include_original: true
            }
        );

        assert_eq!(*cast_as, CastAs::Text);
    }

    #[test]
    fn test_ste_vec_index() {
        let json = json!({
            "v": 2,
            "tables": {
                "documents": {
                    "content": {
                        "cast_as": "jsonb",
                        "indexes": {
                            "ste_vec": {
                                "prefix": "documents.content"
                            }
                        }
                    }
                }
            }
        });

        let encrypt_config = parse(json);
        let ident = Identifier::new("documents", "content");
        let (column, cast_as) = encrypt_config.get(&ident).expect("column exists");

        assert_eq!(
            column.indexes[0].index_type,
            IndexType::SteVec {
                prefix: "documents.content".into()
            }
        );

        assert_eq!(*cast_as, CastAs::JsonB);
    }

    #[test]
    fn test_multiple_indexes() {
        let json = json!({
            "v": 2,
            "tables": {
                "users": {
                    "profile": {
                        "cast_as": "text",
                        "indexes": {
                            "unique": {},
                            "match": {}
                        }
                    }
                }
            }
        });

        let encrypt_config = parse(json);
        let ident = Identifier::new("users", "profile");
        let (column, cast_as) = encrypt_config.get(&ident).expect("column exists");

        assert_eq!(column.indexes.len(), 2);

        assert!(matches!(
            column.indexes[0].index_type,
            IndexType::Unique { .. }
        ));

        assert!(matches!(
            column.indexes[1].index_type,
            IndexType::Match { .. }
        ));

        assert_eq!(*cast_as, CastAs::Text);
    }

    #[test]
    fn test_config_parsing_missing_version_fails() {
        let json = json!({
            "tables": {
                "users": {
                    "email": {
                        "cast_as": "text"
                    }
                }
            }
        });

        let result = serde_json::from_value::<EncryptConfig>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_parsing_unsupported_version_fails() {
        let json = json!({
            "v": 1,
            "tables": {
                "users": {
                    "email": {
                        "cast_as": "text"
                    }
                }
            }
        });

        let result = EncryptConfig::from_str(&json.to_string());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::Error::UnsupportedSchemaVersion(1)
        ));
    }
}
