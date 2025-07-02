//! Safe FFI utility functions for pointer validation and C string conversion.

use crate::{Client, Error};
use libc::c_char;
use std::ffi::{CStr, CString};
use std::ptr;

/// Safely convert a raw client pointer to a reference.
///
/// # Errors
///
/// Returns [`Error::NullPointer`] if the provided pointer is null.
///
/// # Safety
///
/// The caller must ensure the pointer is valid and properly aligned.
pub fn client_ref<'a>(client: *const Client) -> Result<&'a Client, Error> {
    if client.is_null() {
        Err(Error::NullPointer)
    } else {
        unsafe { Ok(&*client) }
    }
}

/// Safely convert a raw C string to a Rust [`String`].
///
/// # Errors
///
/// Returns [`Error::NullPointer`] if the provided pointer is null, or
/// [`Error::Utf8`] if the C string contains invalid UTF-8.
///
/// # Safety
///
/// The caller must ensure the pointer points to a valid null-terminated C string.
pub fn c_str_to_string(c_string_ptr: *const c_char) -> Result<String, Error> {
    if c_string_ptr.is_null() {
        Err(Error::NullPointer)
    } else {
        unsafe {
            let c_string = CStr::from_ptr(c_string_ptr);
            Ok(c_string.to_str()?.to_owned())
        }
    }
}

/// Safely convert an optional C string (can be null) to an [`Option<String>`].
///
/// # Errors
///
/// Returns [`Error::Utf8`] if the C string contains invalid UTF-8.
///
/// # Safety
///
/// If not null, the caller must ensure the pointer points to a valid null-terminated C string.
pub fn optional_c_str_to_string(c_string_ptr: *const c_char) -> Result<Option<String>, Error> {
    if c_string_ptr.is_null() {
        Ok(None)
    } else {
        Ok(Some(c_str_to_string(c_string_ptr)?))
    }
}

/// Convert a Rust [`String`] to a C string pointer.
///
/// # Errors
///
/// Returns [`Error::StringConversion`] if the string contains null bytes.
pub fn string_to_c_str(string: String) -> Result<*mut c_char, Error> {
    CString::new(string)
        .map(|cs| cs.into_raw())
        .map_err(|e| Error::StringConversion(e.to_string()))
}

/// Safely free a boxed client pointer.
///
/// # Safety
///
/// The caller must ensure the pointer was created by [`Box::into_raw`] and hasn't been freed.
pub fn free_boxed_client(client: *mut Client) {
    if !client.is_null() {
        unsafe {
            drop(Box::from_raw(client));
        }
    }
}

/// Safely free a C string created by this library.
///
/// # Safety
///
/// The caller must ensure the pointer was created by [`CString::into_raw`] and hasn't been freed.
pub fn free_c_string(c_string_ptr: *mut c_char) {
    if !c_string_ptr.is_null() {
        unsafe {
            drop(CString::from_raw(c_string_ptr));
        }
    }
}

/// Set an error message in the error output pointer.
///
/// # Safety
///
/// The caller must ensure `error_out` points to a valid mutable pointer.
pub fn set_error(error_out: *mut *mut c_char, error: &Error) {
    if !error_out.is_null() {
        let error_msg = format!("{}", error);
        if let Ok(c_error) = CString::new(error_msg) {
            unsafe {
                *error_out = c_error.into_raw();
            }
        }
    }
}

/// Clear the error output pointer.
///
/// # Safety
///
/// The caller must ensure `error_out` points to a valid mutable pointer.
pub fn clear_error(error_out: *mut *mut c_char) {
    if !error_out.is_null() {
        unsafe {
            *error_out = ptr::null_mut();
        }
    }
}

/// Macro for handling FFI results with proper error handling.
///
/// On success, clears the error output and applies the success transformation.
/// On error, sets the error message and returns a null pointer.
#[macro_export]
macro_rules! handle_ffi_result {
    ($result:expr, $error_out:expr, $success_transform:expr) => {
        match $result {
            Ok(success_value) => {
                $crate::safe_ffi::clear_error($error_out);
                $success_transform(success_value)
            }
            Err(error) => {
                $crate::safe_ffi::set_error($error_out, &error);
                ptr::null_mut()
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::ptr;

    #[test]
    fn test_client_ref_null_pointer() {
        let result = client_ref(ptr::null());
        assert!(matches!(result, Err(Error::NullPointer)));
    }

    #[test]
    fn test_c_str_to_string_valid() {
        let test_string = "Hello, World!";
        let c_string = CString::new(test_string).unwrap();
        let c_string_ptr = c_string.as_ptr();

        let result = c_str_to_string(c_string_ptr);
        assert_eq!(result.unwrap(), test_string);
    }

    #[test]
    fn test_c_str_to_string_null_pointer() {
        let result = c_str_to_string(ptr::null());
        assert!(matches!(result, Err(Error::NullPointer)));
    }

    #[test]
    fn test_c_str_to_string_invalid_utf8() {
        let invalid_bytes = [0xFF, 0xFE, 0x00]; // Invalid UTF-8 sequence + null terminator
        let c_string_ptr = invalid_bytes.as_ptr() as *const c_char;

        let result = c_str_to_string(c_string_ptr);
        assert!(matches!(result, Err(Error::Utf8(_))));
    }

    #[test]
    fn test_optional_c_str_to_string_valid() {
        let test_string = "Optional string";
        let c_string = CString::new(test_string).unwrap();
        let c_string_ptr = c_string.as_ptr();

        let result = optional_c_str_to_string(c_string_ptr);
        assert_eq!(result.unwrap(), Some(test_string.to_string()));
    }

    #[test]
    fn test_optional_c_str_to_string_null() {
        let result = optional_c_str_to_string(ptr::null());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_string_to_c_str_valid() {
        let test_string = "Test string".to_string();
        let result = string_to_c_str(test_string.clone());

        assert!(result.is_ok());
        let c_string_ptr = result.unwrap();

        let restored = unsafe { CStr::from_ptr(c_string_ptr) };
        assert_eq!(restored.to_str().unwrap(), test_string);

        free_c_string(c_string_ptr);
    }

    #[test]
    fn test_string_to_c_str_with_null_byte() {
        let test_string = "String\0with\0nulls".to_string();
        let result = string_to_c_str(test_string);

        assert!(matches!(result, Err(Error::StringConversion(_))));
    }

    #[test]
    fn test_free_boxed_client_null() {
        free_boxed_client(ptr::null_mut());
    }

    #[test]
    fn test_free_c_string_null() {
        free_c_string(ptr::null_mut());
    }

    #[test]
    fn test_free_c_string_valid() {
        let c_string = CString::new("test").unwrap();
        let c_string_ptr = c_string.into_raw();

        free_c_string(c_string_ptr);
    }

    #[test]
    fn test_set_error_null_pointer() {
        let error = Error::NullPointer;
        set_error(ptr::null_mut(), &error);
    }

    #[test]
    fn test_set_error_valid() {
        let mut error_ptr: *mut c_char = ptr::null_mut();
        let error_out = &mut error_ptr as *mut *mut c_char;
        let error = Error::NullPointer;

        set_error(error_out, &error);

        assert!(!error_ptr.is_null());

        let error_msg = unsafe { CStr::from_ptr(error_ptr) };
        assert!(error_msg.to_str().unwrap().contains("null pointer"));

        free_c_string(error_ptr);
    }

    #[test]
    fn test_clear_error_null_pointer() {
        clear_error(ptr::null_mut());
    }

    #[test]
    fn test_clear_error_valid() {
        let mut error_ptr: *mut c_char = CString::new("test error").unwrap().into_raw();
        let error_out = &mut error_ptr as *mut *mut c_char;

        clear_error(error_out);

        assert!(error_ptr.is_null());
    }

    #[test]
    fn test_handle_ffi_result_macro_success() {
        let mut error_ptr: *mut c_char = ptr::null_mut();
        let error_out = &mut error_ptr as *mut *mut c_char;

        let result: Result<String, Error> = Ok("success".to_string());
        let output = handle_ffi_result!(result, error_out, |string| {
            CString::new(string).unwrap().into_raw()
        });

        assert!(!output.is_null());
        assert!(error_ptr.is_null());

        free_c_string(output);
    }

    #[test]
    fn test_handle_ffi_result_macro_error() {
        let mut error_ptr: *mut c_char = ptr::null_mut();
        let error_out = &mut error_ptr as *mut *mut c_char;

        let result: Result<String, Error> = Err(Error::NullPointer);
        let output = handle_ffi_result!(result, error_out, |string| {
            CString::new(string).unwrap().into_raw()
        });

        assert!(output.is_null());
        assert!(!error_ptr.is_null());

        let error_msg = unsafe { CStr::from_ptr(error_ptr) };
        assert!(error_msg.to_str().unwrap().contains("null pointer"));

        free_c_string(error_ptr);
    }
}
