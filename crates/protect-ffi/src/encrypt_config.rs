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
    pub fn into_column_config(self, name: &str) -> ColumnConfig {
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

    /// Parse valid JSON configuration into a [`HashMap`] mapping [`Identifier`] to
    /// [`ColumnConfig`] for test assertions.
    fn parse_config(json: serde_json::Value) -> HashMap<Identifier, (ColumnConfig, CastAs)> {
        serde_json::from_value::<EncryptConfig>(json)
            .expect("valid config JSON")
            .into_config_map()
    }

    /// Create a minimal valid configuration JSON with a single column for testing.
    fn minimal_config(table: &str, column: &str, cast_as: &str) -> serde_json::Value {
        json!({
            "v": 2,
            "tables": {
                table: {
                    column: {
                        "cast_as": cast_as
                    }
                }
            }
        })
    }

    /// Create a configuration JSON with encryption indexes for testing.
    fn config_with_indexes(
        table: &str,
        column: &str,
        cast_as: &str,
        indexes: serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "v": 2,
            "tables": {
                table: {
                    column: {
                        "cast_as": cast_as,
                        "indexes": indexes
                    }
                }
            }
        })
    }

    /// Retrieve column configuration from parsed configuration map for test assertions.
    fn get_column_config<'a>(
        parsed_config: &'a HashMap<Identifier, (ColumnConfig, CastAs)>,
        table: &str,
        column: &str,
    ) -> &'a (ColumnConfig, CastAs) {
        let identifier = Identifier::new(table, column);
        parsed_config
            .get(&identifier)
            .expect("column should exist in config")
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
    fn test_cast_as_to_column_type_conversion() {
        let test_cases = [
            (CastAs::Text, ColumnType::Utf8Str),
            (CastAs::Boolean, ColumnType::Boolean),
            (CastAs::SmallInt, ColumnType::SmallInt),
            (CastAs::Int, ColumnType::Int),
            (CastAs::BigInt, ColumnType::BigInt),
            (CastAs::Real, ColumnType::Float),
            (CastAs::Double, ColumnType::Float),
            (CastAs::Date, ColumnType::Date),
            (CastAs::JsonB, ColumnType::JsonB),
        ];

        for (cast_as, expected_column_type) in test_cases {
            assert_eq!(ColumnType::from(cast_as), expected_column_type);
        }
    }

    #[test]
    fn test_identifier_creation() {
        let id = Identifier::new("orders", "customer_id");
        assert_eq!(id.table, "orders");
        assert_eq!(id.column, "customer_id");
    }

    #[test]
    fn test_identifier_creation_with_unicode() {
        let id = Identifier::new("ユーザー", "名前");
        assert_eq!(id.table, "ユーザー");
        assert_eq!(id.column, "名前");
    }

    #[test]
    fn test_supported_schema_versions() {
        for &version in SUPPORTED_SCHEMA_VERSIONS {
            let config_json = json!({
                "v": version,
                "tables": {}
            });
            let result = EncryptConfig::from_str(&config_json.to_string());
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_config_parsing_missing_version_fails() {
        let invalid_json = json!({
            "tables": {
                "users": {
                    "email": {"cast_as": "text"}
                }
            }
        });

        let result = serde_json::from_value::<EncryptConfig>(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_parsing_unsupported_version_fails() {
        let invalid_json = json!({
            "v": 1,
            "tables": {
                "users": {
                    "email": {"cast_as": "text"}
                }
            }
        });

        let result = EncryptConfig::from_str(&invalid_json.to_string());
        assert!(result.is_err());

        match result.unwrap_err() {
            crate::Error::UnsupportedSchemaVersion(version) => {
                assert_eq!(version, 1);
            }
            other => panic!(
                "expected `UnsupportedSchemaVersion` error, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_basic_config_parsing() {
        let config = minimal_config("users", "name", "text");
        let parsed_config = parse_config(config);
        let (column_config, cast_as) = get_column_config(&parsed_config, "users", "name");

        assert_eq!(column_config.cast_type, ColumnType::Utf8Str);
        assert_eq!(column_config.name, "name");
        assert_eq!(*cast_as, CastAs::Text);
        assert!(column_config.indexes.is_empty());
    }

    #[test]
    fn test_config_parsing_all_cast_types() {
        let cast_types = [
            ("text", CastAs::Text, ColumnType::Utf8Str),
            ("boolean", CastAs::Boolean, ColumnType::Boolean),
            ("small_int", CastAs::SmallInt, ColumnType::SmallInt),
            ("int", CastAs::Int, ColumnType::Int),
            ("big_int", CastAs::BigInt, ColumnType::BigInt),
            ("real", CastAs::Real, ColumnType::Float),
            ("double", CastAs::Double, ColumnType::Float),
            ("date", CastAs::Date, ColumnType::Date),
            ("jsonb", CastAs::JsonB, ColumnType::JsonB),
        ];

        for (cast_as, expected_cast, expected_type) in cast_types {
            let config_json = minimal_config("products", "value", cast_as);
            let parsed_config = parse_config(config_json);
            let (column_config, cast_as) = get_column_config(&parsed_config, "products", "value");

            assert_eq!(*cast_as, expected_cast);
            assert_eq!(column_config.cast_type, expected_type);
        }
    }

    #[test]
    fn test_empty_config() {
        let config_json = json!({
            "v": 2,
            "tables": {}
        });
        let parsed_config = parse_config(config_json);

        assert!(parsed_config.is_empty());
    }

    #[test]
    fn test_unique_index_basic() {
        let indexes = json!({"unique": {}});
        let config_json = config_with_indexes("users", "email", "text", indexes);
        let parsed_config = parse_config(config_json);
        let (column_config, cast_as) = get_column_config(&parsed_config, "users", "email");

        assert_eq!(column_config.indexes.len(), 1);
        assert_eq!(
            column_config.indexes[0].index_type,
            IndexType::Unique {
                token_filters: vec![]
            }
        );
        assert_eq!(*cast_as, CastAs::Text);
    }

    #[test]
    fn test_unique_index_with_token_filters() {
        let indexes = json!({
            "unique": {
                "token_filters": [
                    {"kind": "downcase"}
                ]
            }
        });
        let config_json = config_with_indexes("users", "username", "text", indexes);
        let parsed_config = parse_config(config_json);
        let (column_config, cast_as) = get_column_config(&parsed_config, "users", "username");

        assert_eq!(column_config.indexes.len(), 1);
        assert_eq!(
            column_config.indexes[0].index_type,
            IndexType::Unique {
                token_filters: vec![TokenFilter::Downcase]
            }
        );
        assert_eq!(*cast_as, CastAs::Text);
    }

    #[test]
    fn test_ore_index() {
        let indexes = json!({"ore": {}});
        let config_json = config_with_indexes("users", "age", "int", indexes);
        let parsed_config = parse_config(config_json);
        let (column_config, cast_as) = get_column_config(&parsed_config, "users", "age");

        assert_eq!(column_config.indexes.len(), 1);
        assert_eq!(column_config.indexes[0].index_type, IndexType::Ore);
        assert_eq!(*cast_as, CastAs::Int);
    }

    #[test]
    fn test_match_index_defaults() {
        let indexes = json!({"match": {}});
        let config_json = config_with_indexes("posts", "content", "text", indexes);
        let parsed_config = parse_config(config_json);
        let (column_config, cast_as) = get_column_config(&parsed_config, "posts", "content");

        assert_eq!(column_config.indexes.len(), 1);
        assert_eq!(
            column_config.indexes[0].index_type,
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
        let indexes = json!({
            "match": {
                "tokenizer": {
                    "kind": "ngram",
                    "token_length": 3,
                },
                "token_filters": [
                    {"kind": "downcase"}
                ],
                "k": 8,
                "m": 1024,
                "include_original": true
            }
        });
        let config_json = config_with_indexes("articles", "description", "text", indexes);
        let parsed_config = parse_config(config_json);
        let (column_config, cast_as) = get_column_config(&parsed_config, "articles", "description");

        assert_eq!(column_config.indexes.len(), 1);
        assert_eq!(
            column_config.indexes[0].index_type,
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
        let indexes = json!({
            "ste_vec": {
                "prefix": "documents.metadata"
            }
        });
        let config_json = config_with_indexes("documents", "metadata", "jsonb", indexes);
        let parsed_config = parse_config(config_json);
        let (column_config, cast_as) = get_column_config(&parsed_config, "documents", "metadata");

        assert_eq!(column_config.indexes.len(), 1);
        assert_eq!(
            column_config.indexes[0].index_type,
            IndexType::SteVec {
                prefix: "documents.metadata".into()
            }
        );
        assert_eq!(*cast_as, CastAs::JsonB);
    }

    #[test]
    fn test_multiple_indexes() {
        let indexes = json!({
            "unique": {},
            "match": {}
        });
        let config_json = config_with_indexes("users", "bio", "text", indexes);
        let parsed_config = parse_config(config_json);
        let (column_config, cast_as) = get_column_config(&parsed_config, "users", "bio");

        assert_eq!(column_config.indexes.len(), 2);

        let index_types: Vec<_> = column_config
            .indexes
            .iter()
            .map(|index| &index.index_type)
            .collect();

        let has_unique = index_types
            .iter()
            .any(|idx| matches!(idx, IndexType::Unique { .. }));
        let has_match = index_types
            .iter()
            .any(|idx| matches!(idx, IndexType::Match { .. }));

        assert!(has_unique);
        assert!(has_match);
        assert_eq!(*cast_as, CastAs::Text);
    }

    #[test]
    fn test_multiple_tables_and_columns() {
        let config_json = json!({
            "v": 2,
            "tables": {
                "users": {
                    "email": {"cast_as": "text"},
                    "age": {"cast_as": "int"}
                },
                "posts": {
                    "title": {"cast_as": "text"},
                    "published": {"cast_as": "boolean"}
                }
            }
        });
        let parsed_config = parse_config(config_json);

        assert_eq!(parsed_config.len(), 4);

        let (email_config, email_cast) = get_column_config(&parsed_config, "users", "email");
        assert_eq!(*email_cast, CastAs::Text);
        assert_eq!(email_config.name, "email");

        let (age_config, age_cast) = get_column_config(&parsed_config, "users", "age");
        assert_eq!(*age_cast, CastAs::Int);
        assert_eq!(age_config.name, "age");

        let (title_config, title_cast) = get_column_config(&parsed_config, "posts", "title");
        assert_eq!(*title_cast, CastAs::Text);
        assert_eq!(title_config.name, "title");

        let (published_config, published_cast) =
            get_column_config(&parsed_config, "posts", "published");
        assert_eq!(*published_cast, CastAs::Boolean);
        assert_eq!(published_config.name, "published");
    }

    #[test]
    fn test_config_with_unicode_table_and_column_names() {
        let config_json = json!({
            "v": 2,
            "tables": {
                "ユーザー": {
                    "名前": {"cast_as": "text"}
                }
            }
        });
        let parsed_config = parse_config(config_json);
        let (column_config, cast_as) = get_column_config(&parsed_config, "ユーザー", "名前");

        assert_eq!(*cast_as, CastAs::Text);
        assert_eq!(column_config.name, "名前");
    }

    #[test]
    fn test_config_parsing_invalid_cast_type_fails() {
        let invalid_json = json!({
            "v": 2,
            "tables": {
                "users": {
                    "email": {"cast_as": "invalid_type"}
                }
            }
        });

        let result = serde_json::from_value::<EncryptConfig>(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_parsing_malformed_json_fails() {
        let malformed_json = r#"{"v": 2, "tables": {"users": {"email": {"cast_as": "text""#;
        let result = EncryptConfig::from_str(malformed_json);
        assert!(result.is_err());

        match result.unwrap_err() {
            crate::Error::Parse(_) => {
                // Expected parse error
            }
            other => panic!("expected `Parse` error, got: {:?}", other),
        }
    }
}
