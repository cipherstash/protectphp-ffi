<?php

declare(strict_types=1);

namespace CipherStash\Protect\FFI\Exceptions;

use Exception;

/**
 * Exception thrown when the platform loader encounters an error.
 */
final class LoaderException extends Exception
{
    /**
     * Create a new exception for when the native library is not readable.
     */
    public static function nativeLibraryNotReadable(string $platform, string $path): self
    {
        return new self(
            "Native library for platform [{$platform}] is not readable at [{$path}]. ".
            'Please check file permissions or ensure the file exists.'
        );
    }

    /**
     * Create a new exception for unsupported platforms.
     */
    public static function unsupportedPlatform(string $platform): self
    {
        return new self(
            "Platform [{$platform}] is not supported. ".
            'Supported platforms: darwin-arm64, darwin-x64, linux-arm64-gnu, linux-x64-gnu, win32-x64-msvc.'
        );
    }
}
