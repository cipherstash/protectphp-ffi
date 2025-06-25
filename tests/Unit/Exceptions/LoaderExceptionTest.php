<?php

declare(strict_types=1);

namespace CipherStash\Protect\FFI\Tests\Unit\Exceptions;

use CipherStash\Protect\FFI\Exceptions\LoaderException;
use PHPUnit\Framework\TestCase;

class LoaderExceptionTest extends TestCase
{
    public function test_native_library_not_readable(): void
    {
        $platform = 'darwin-x64';
        $path = '/path/to/library.dylib';
        $exception = LoaderException::nativeLibraryNotReadable($platform, $path);

        $this->assertInstanceOf(LoaderException::class, $exception);
        $this->assertNotEmpty($exception->getMessage());
    }

    public function test_unsupported_platform(): void
    {
        $platform = 'unknown-platform';
        $exception = LoaderException::unsupportedPlatform($platform);

        $this->assertInstanceOf(LoaderException::class, $exception);
        $this->assertNotEmpty($exception->getMessage());
    }
}
