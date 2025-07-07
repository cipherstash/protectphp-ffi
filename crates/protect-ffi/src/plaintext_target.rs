//! [`PlaintextTarget`] creation with workaround for upstream SDK.

use cipherstash_client::{
    encryption::PlaintextTarget,
    schema::{column::IndexType, ColumnConfig, ColumnType},
};

use crate::Error;

/// Creates a [`PlaintextTarget`] with specialized handling for JSONB columns with `ste_vec` indexes.
///
/// For JSONB columns configured with `ste_vec` indexes, JSON strings are pre-parsed to
/// [`serde_json::Value`] to ensure correct type resolution in the upstream SDK. The expected
/// behavior in the upstream SDK is to resolve JSON strings as
/// [`cipherstash_client::encryption::Plaintext::Utf8Str`] instead of
/// [`cipherstash_client::encryption::Plaintext::JsonB`], so this pre-parsing step ensures the
/// correct type inference for `ste_vec` index compatibility.
///
/// # Errors
///
/// Returns an error if the input string is not valid JSON when targeting a JSONB column
/// with `ste_vec` indexes.
pub fn new(plaintext: String, column_config: &ColumnConfig) -> Result<PlaintextTarget, Error> {
    let needs_json_parsing = column_config.cast_type == ColumnType::JsonB
        && column_config
            .indexes
            .iter()
            .any(|idx| matches!(idx.index_type, IndexType::SteVec { .. }));

    if needs_json_parsing {
        let json_value: serde_json::Value =
            serde_json::from_str(&plaintext).map_err(Error::Parse)?;
        Ok(PlaintextTarget::new(json_value, column_config.clone()))
    } else {
        Ok(PlaintextTarget::new(plaintext, column_config.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_text_plaintext() {
        let column_config = ColumnConfig::build("email".to_string()).casts_as(ColumnType::Utf8Str);
        let plaintext = "john@example.com".to_string();

        let result = new(plaintext, &column_config);

        assert!(result.is_ok());
    }

    #[test]
    fn test_new_with_valid_jsonb() {
        let column_config = ColumnConfig::build("metadata".to_string()).casts_as(ColumnType::JsonB);
        let plaintext = r#"{"name": "정주영", "age": 85}"#.to_string();

        let result = new(plaintext, &column_config);

        assert!(result.is_ok());
    }

    #[test]
    fn test_new_with_jsonb_no_validation() {
        let column_config = ColumnConfig::build("metadata".to_string()).casts_as(ColumnType::JsonB);
        let invalid_json = "not valid json".to_string();

        // JSONB columns without `ste_vec` indexes don't validate JSON syntax
        let result = new(invalid_json, &column_config);

        assert!(result.is_ok());
    }
}
