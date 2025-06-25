//! PlaintextTarget creation with workarounds for upstream SDK limitations.

use cipherstash_client::{
    encryption::PlaintextTarget,
    schema::{column::IndexType, ColumnConfig, ColumnType},
};

use crate::Error;

/// Creates a PlaintextTarget with specialized handling for JSONB columns with ste_vec indexes.
///
/// # Workaround
///
/// This function works around a type resolution limitation in cipherstash-client v0.22.2
/// where JSON string inputs to JSONB columns configured with `ste_vec` indexes
/// are resolved as `Plaintext::Utf8Str` instead of the expected `Plaintext::JsonB`.
///
/// **Context:** The upstream SDK's type resolution has incomplete support for
/// the interaction between JSONB casting and structured text encryption vectors,
/// resulting in string type inference instead of JSONB type.
///
/// **Solution:** Pre-parse JSON strings to `serde_json::Value` to bypass the
/// type inference limitation and directly provide the correct input type.
///
/// # TODO
///
/// Remove this workaround when cipherstash-client addresses the type resolution limitation.
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
    #[test]
    fn test_json_parsing_logic() {
        let valid_json = r#"{"key": "value"}"#;
        let result = serde_json::from_str::<serde_json::Value>(valid_json);
        assert!(result.is_ok());

        let invalid_json = "not valid json";
        let result = serde_json::from_str::<serde_json::Value>(invalid_json);
        assert!(result.is_err());
    }
}
