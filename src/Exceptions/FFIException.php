<?php

declare(strict_types=1);

namespace CipherStash\Protect\FFI\Exceptions;

use Exception;

/**
 * Exception thrown when FFI operations encounter failures.
 */
final class FFIException extends Exception
{
    /**
     * Create a new exception for when FFI client initialization fails.
     */
    public static function failedToInitializeClient(string $reason): self
    {
        return new self("Failed to initialize FFI client instance: [{$reason}].");
    }

    /**
     * Create a new exception for when FFI client is not initialized.
     */
    public static function clientNotInitialized(): self
    {
        return new self('The FFI client instance has not been initialized. Ensure the library is properly loaded before making any calls.');
    }

    /**
     * Create a new exception for when client creation fails.
     */
    public static function clientCreationFailed(string $reason): self
    {
        return new self("Failed to create the FFI client: [{$reason}].");
    }

    /**
     * Create a new exception for when the header file is not readable.
     */
    public static function headerNotReadable(string $path): self
    {
        return new self("The FFI header file is not readable at [{$path}]. Please check file permissions or ensure the file exists.");
    }

    /**
     * Create a new exception for when string pointer creation fails.
     */
    public static function stringPointerCreationFailed(): self
    {
        return new self('Failed to create string pointer for FFI operation.');
    }

    /**
     * Create a new exception for encryption failures.
     */
    public static function failedToEncrypt(string $reason): self
    {
        return new self("Failed to encrypt data through FFI operation: [{$reason}].");
    }

    /**
     * Create a new exception for decryption failures.
     */
    public static function failedToDecrypt(string $reason): self
    {
        return new self("Failed to decrypt data through FFI operation: [{$reason}].");
    }

    /**
     * Create a new exception for bulk encryption failures.
     */
    public static function failedToBulkEncrypt(string $reason): self
    {
        return new self("Failed to bulk encrypt data through FFI operation: [{$reason}].");
    }

    /**
     * Create a new exception for bulk decryption failures.
     */
    public static function failedToBulkDecrypt(string $reason): self
    {
        return new self("Failed to bulk decrypt data through FFI operation: [{$reason}].");
    }

    /**
     * Create a new exception for when search term creation fails.
     */
    public static function failedToCreateSearchTerms(string $reason): self
    {
        return new self("Failed to create search terms: [{$reason}].");
    }

    /**
     * Create a new exception for string conversion failures.
     */
    public static function failedToConvertString(string $reason): self
    {
        return new self("Failed to convert C string to PHP string from FFI operation: [{$reason}].");
    }
}
