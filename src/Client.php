<?php

declare(strict_types=1);

namespace CipherStash\Protect\FFI;

use CipherStash\Protect\FFI\Exceptions\FFIException;
use Throwable;

/**
 * Handles encryption and decryption operations using the CipherStash Client SDK.
 *
 * Provides individual and bulk operations, plus search term generation for
 * querying encrypted data.
 */
class Client
{
    /**
     * The FFI instance.
     */
    private \FFI $ffi;

    /**
     * Indicates whether the client has been successfully initialized.
     */
    private bool $initialized = false;

    /**
     * Create a new client instance.
     *
     * Initializes the client by loading the Rust library and C header definitions.
     *
     * @throws FFIException When the header file is not readable or client initialization fails
     */
    public function __construct()
    {
        try {
            $this->ffi = $this->createFFIInstance();

            $this->initialized = true;
        } catch (Throwable $e) {
            throw FFIException::failedToInitializeClient($e->getMessage());
        }
    }

    /**
     * Create a new client instance with the provided encryption configuration.
     *
     * Authentication is handled through environment variables.
     *
     * @param  string  $configJson  Encryption configuration as a JSON string
     *
     * @throws FFIException When client creation fails
     */
    public function newClient(string $configJson): \FFI\CData
    {
        $client = $this->executeFFIOperation(function (\FFI\CData $errorPtr) use ($configJson): ?\FFI\CData {
            $result = $this->ffi->new_client($configJson, \FFI::addr($errorPtr));

            return $result instanceof \FFI\CData ? $result : null;
        }, FFIException::clientCreationFailed(...));

        return $client;
    }

    /**
     * Encrypt plaintext for a specific table column.
     *
     * @param  string|null  $contextJson  Encryption context as a JSON string
     * @return string Encrypted envelope as a JSON string
     *
     * @throws FFIException When encryption fails
     */
    public function encrypt(\FFI\CData $client, string $plaintext, string $column, string $table, ?string $contextJson = null): string
    {
        $resultPtr = $this->executeFFIOperation(function (\FFI\CData $errorPtr) use ($client, $plaintext, $column, $table, $contextJson): ?\FFI\CData {
            $result = $this->ffi->encrypt(
                $client,
                $plaintext,
                $column,
                $table,
                $contextJson,
                \FFI::addr($errorPtr)
            );

            return $result instanceof \FFI\CData ? $result : null;
        }, FFIException::failedToEncrypt(...));

        $result = $this->convertStringPointer($resultPtr);

        $this->freeStringPointer($resultPtr);

        return $result;
    }

    /**
     * Decrypt ciphertext back to the original plaintext.
     *
     * @param  string|null  $contextJson  Decryption context as a JSON string
     * @return string The decrypted plaintext as a string
     *
     * @throws FFIException When decryption fails
     */
    public function decrypt(\FFI\CData $client, string $ciphertext, ?string $contextJson = null): string
    {
        $resultPtr = $this->executeFFIOperation(function (\FFI\CData $errorPtr) use ($client, $ciphertext, $contextJson): ?\FFI\CData {
            $result = $this->ffi->decrypt(
                $client,
                $ciphertext,
                $contextJson,
                \FFI::addr($errorPtr)
            );

            return $result instanceof \FFI\CData ? $result : null;
        }, FFIException::failedToDecrypt(...));

        $result = $this->convertStringPointer($resultPtr);

        $this->freeStringPointer($resultPtr);

        return $result;
    }

    /**
     * Encrypt multiple values in a single batch operation.
     *
     * @param  string  $itemsJson  Items to encrypt as a JSON string
     * @return string Encrypted envelopes as a JSON string
     *
     * @throws FFIException When encryption fails
     */
    public function encryptBulk(\FFI\CData $client, string $itemsJson): string
    {
        $resultPtr = $this->executeFFIOperation(function (\FFI\CData $errorPtr) use ($client, $itemsJson): ?\FFI\CData {
            $result = $this->ffi->encrypt_bulk($client, $itemsJson, \FFI::addr($errorPtr));

            return $result instanceof \FFI\CData ? $result : null;
        }, FFIException::failedToBulkEncrypt(...));

        $result = $this->convertStringPointer($resultPtr);

        $this->freeStringPointer($resultPtr);

        return $result;
    }

    /**
     * Decrypt multiple ciphertext values in a single batch operation.
     *
     * @param  string  $itemsJson  Items to decrypt as a JSON string
     * @return string Decrypted plaintext strings as a JSON string
     *
     * @throws FFIException When decryption fails
     */
    public function decryptBulk(\FFI\CData $client, string $itemsJson): string
    {
        $resultPtr = $this->executeFFIOperation(function (\FFI\CData $errorPtr) use ($client, $itemsJson): ?\FFI\CData {
            $result = $this->ffi->decrypt_bulk($client, $itemsJson, \FFI::addr($errorPtr));

            return $result instanceof \FFI\CData ? $result : null;
        }, FFIException::failedToBulkDecrypt(...));

        $result = $this->convertStringPointer($resultPtr);

        $this->freeStringPointer($resultPtr);

        return $result;
    }

    /**
     * Create search terms for querying encrypted data.
     *
     * @param  string  $itemsJson  Items to create search terms for as a JSON string
     * @return string Search terms as a JSON string
     *
     * @throws FFIException When search term creation fails
     */
    public function createSearchTerms(\FFI\CData $client, string $itemsJson): string
    {
        $resultPtr = $this->executeFFIOperation(function (\FFI\CData $errorPtr) use ($client, $itemsJson): ?\FFI\CData {
            $result = $this->ffi->create_search_terms($client, $itemsJson, \FFI::addr($errorPtr));

            return $result instanceof \FFI\CData ? $result : null;
        }, FFIException::failedToCreateSearchTerms(...));

        $result = $this->convertStringPointer($resultPtr);

        $this->freeStringPointer($resultPtr);

        return $result;
    }

    /**
     * Release the client instance and free associated resources.
     *
     * This method should be called when you're done with the client
     * to prevent memory leaks and properly clean up resources.
     */
    public function freeClient(\FFI\CData $client): void
    {
        try {
            $this->ffi->free_client($client);
        } catch (Throwable) {
            // Silently ignore any exceptions during cleanup
        }
    }

    /**
     * Execute an FFI operation with error handling.
     *
     * @param  callable(\FFI\CData $errorPtr): ?\FFI\CData  $operation
     * @param  callable(string $message): FFIException  $createException
     * @return \FFI\CData FFI pointer result
     *
     * @throws FFIException When client is not initialized or FFI operation fails
     */
    private function executeFFIOperation(callable $operation, callable $createException): \FFI\CData
    {
        if (! $this->isInitialized()) {
            throw FFIException::clientNotInitialized();
        }

        $errorPtr = $this->createStringPointer();

        try {
            $result = $operation($errorPtr);

            if ($result === null) {
                $message = $this->convertStringPointer($errorPtr);

                throw $createException($message);
            }

            return $result;
        } catch (FFIException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw $createException($e->getMessage());
        } finally {
            $this->freeStringPointer($errorPtr);
        }
    }

    /**
     * Check if the client has been initialized.
     */
    private function isInitialized(): bool
    {
        return $this->initialized;
    }

    /**
     * Create the FFI instance with library and header definitions.
     *
     * @throws FFIException When FFI instance creation fails
     */
    private function createFFIInstance(): \FFI
    {
        $libraryPath = Loader::getLibraryPath();
        $headerContent = $this->loadHeaderFile();

        return \FFI::cdef($headerContent, $libraryPath);
    }

    /**
     * Load and validate the C header file content.
     *
     * @throws FFIException When header file is not readable
     */
    private function loadHeaderFile(): string
    {
        $headerPath = $this->getHeaderPath();
        $content = file_get_contents($headerPath);

        if ($content === false) {
            throw FFIException::headerNotReadable($headerPath);
        }

        return $content;
    }

    /**
     * Get the absolute path to the C header file.
     */
    private function getHeaderPath(): string
    {
        return dirname(__DIR__).'/include/protectphp.h';
    }

    /**
     * Create a string pointer for FFI operations.
     */
    private function createStringPointer(): \FFI\CData
    {
        $pointer = $this->ffi->new('char*');

        if ($pointer === null) {
            throw FFIException::stringPointerCreationFailed();
        }

        return $pointer;
    }

    /**
     * Free the memory allocated for a string pointer.
     */
    private function freeStringPointer(\FFI\CData $stringPtr): void
    {
        try {
            $this->ffi->free_string($stringPtr);
        } catch (Throwable) {
            // Silently ignore any exceptions during cleanup
        }
    }

    /**
     * Convert a C string pointer from an FFI operation to a PHP string.
     *
     * @throws FFIException When string conversion fails
     */
    private function convertStringPointer(\FFI\CData $cStringPtr): string
    {
        try {
            return \FFI::string($cStringPtr);
        } catch (Throwable $e) {
            throw FFIException::failedToConvertString($e->getMessage());
        }
    }
}
