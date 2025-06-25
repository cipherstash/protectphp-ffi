<?php

declare(strict_types=1);

namespace CipherStash\Protect\FFI\Tests\Unit\Exceptions;

use CipherStash\Protect\FFI\Exceptions\FFIException;
use PHPUnit\Framework\TestCase;

class FFIExceptionTest extends TestCase
{
    public function test_failed_to_initialize_client(): void
    {
        $reason = 'Config missing required field';
        $exception = FFIException::failedToInitializeClient($reason);

        $this->assertInstanceOf(FFIException::class, $exception);
        $this->assertNotEmpty($exception->getMessage());
    }

    public function test_client_not_initialized(): void
    {
        $exception = FFIException::clientNotInitialized();

        $this->assertInstanceOf(FFIException::class, $exception);
        $this->assertNotEmpty($exception->getMessage());
    }

    public function test_header_not_readable(): void
    {
        $path = '/path/to/header.h';
        $exception = FFIException::headerNotReadable($path);

        $this->assertInstanceOf(FFIException::class, $exception);
        $this->assertNotEmpty($exception->getMessage());
    }

    public function test_client_creation_failed(): void
    {
        $reason = 'Invalid configuration provided';
        $exception = FFIException::clientCreationFailed($reason);

        $this->assertInstanceOf(FFIException::class, $exception);
        $this->assertNotEmpty($exception->getMessage());
    }

    public function test_failed_to_encrypt(): void
    {
        $reason = 'Invalid plaintext format';
        $exception = FFIException::failedToEncrypt($reason);

        $this->assertInstanceOf(FFIException::class, $exception);
        $this->assertNotEmpty($exception->getMessage());
    }

    public function test_failed_to_decrypt(): void
    {
        $reason = 'Invalid ciphertext format';
        $exception = FFIException::failedToDecrypt($reason);

        $this->assertInstanceOf(FFIException::class, $exception);
        $this->assertNotEmpty($exception->getMessage());
    }

    public function test_failed_to_bulk_encrypt(): void
    {
        $reason = 'Invalid bulk encryption input';
        $exception = FFIException::failedToBulkEncrypt($reason);

        $this->assertInstanceOf(FFIException::class, $exception);
        $this->assertNotEmpty($exception->getMessage());
    }

    public function test_failed_to_bulk_decrypt(): void
    {
        $reason = 'Invalid bulk decryption input';
        $exception = FFIException::failedToBulkDecrypt($reason);

        $this->assertInstanceOf(FFIException::class, $exception);
        $this->assertNotEmpty($exception->getMessage());
    }

    public function test_failed_to_convert_string(): void
    {
        $reason = 'Null pointer encountered';
        $exception = FFIException::failedToConvertString($reason);

        $this->assertInstanceOf(FFIException::class, $exception);
        $this->assertNotEmpty($exception->getMessage());
    }

    public function test_string_pointer_creation_failed(): void
    {
        $exception = FFIException::stringPointerCreationFailed();

        $this->assertInstanceOf(FFIException::class, $exception);
        $this->assertNotEmpty($exception->getMessage());
    }

    public function test_failed_to_create_search_terms(): void
    {
        $reason = 'Unknown column in configuration';
        $exception = FFIException::failedToCreateSearchTerms($reason);

        $this->assertInstanceOf(FFIException::class, $exception);
        $this->assertNotEmpty($exception->getMessage());
    }
}
