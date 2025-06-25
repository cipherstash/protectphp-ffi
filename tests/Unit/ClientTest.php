<?php

declare(strict_types=1);

namespace CipherStash\Protect\FFI\Tests\Unit;

use CipherStash\Protect\FFI\Client;
use CipherStash\Protect\FFI\Exceptions\FFIException;
use PHPUnit\Framework\TestCase;

class ClientTest extends TestCase
{
    public function test_constructor_initializes_client_successfully(): void
    {
        $client = new Client;
        $reflection = new \ReflectionClass($client);

        $initializedProperty = $reflection->getProperty('initialized');
        $initializedProperty->setAccessible(true);
        $this->assertTrue($initializedProperty->getValue($client));

        $ffiProperty = $reflection->getProperty('ffi');
        $ffiProperty->setAccessible(true);
        $this->assertInstanceOf(\FFI::class, $ffiProperty->getValue($client));
    }

    public function test_load_header_file_returns_string_content(): void
    {
        $client = new Client;
        $reflection = new \ReflectionClass($client);
        $method = $reflection->getMethod('loadHeaderFile');
        $method->setAccessible(true);

        $content = $method->invoke($client);
        $this->assertIsString($content);
        $this->assertNotEmpty($content);
    }

    public function test_get_header_path_returns_valid_path(): void
    {
        $client = new Client;
        $reflection = new \ReflectionClass($client);
        $method = $reflection->getMethod('getHeaderPath');
        $method->setAccessible(true);

        $path = $method->invoke($client);

        $this->assertIsString($path);
        $this->assertStringEndsWith('protectphp.h', $path);
        $this->assertStringContainsString('include/', $path);
    }

    public function test_execute_ffi_operation_throws_exception_when_not_initialized(): void
    {
        $client = new Client;
        $reflection = new \ReflectionClass($client);

        $initializedProperty = $reflection->getProperty('initialized');
        $initializedProperty->setAccessible(true);
        $initializedProperty->setValue($client, false);

        $method = $reflection->getMethod('executeFFIOperation');
        $method->setAccessible(true);

        $this->expectException(FFIException::class);

        $method->invoke($client, function () {
            return null;
        }, function (string $errorMessage) {
            return FFIException::failedToEncrypt($errorMessage);
        });
    }
}
