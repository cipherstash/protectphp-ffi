<?php

declare(strict_types=1);

namespace CipherStash\Protect\FFI;

use CipherStash\Protect\FFI\Exceptions\LoaderException;

/**
 * Handles loading platform-specific native libraries for FFI bindings.
 */
class Loader
{
    /**
     * Platform-specific library paths in priority order.
     *
     * @var array<string, array<string>>
     */
    private static array $platforms = [
        'darwin-arm64' => [
            'target/aarch64-apple-darwin/release/libprotect_ffi.dylib',
            'platforms/darwin-arm64/libprotect_ffi.dylib',
        ],
        'darwin-x64' => [
            'target/x86_64-apple-darwin/release/libprotect_ffi.dylib',
            'platforms/darwin-x64/libprotect_ffi.dylib',
        ],
        'linux-arm64-gnu' => [
            'target/aarch64-unknown-linux-gnu/release/libprotect_ffi.so',
            'platforms/linux-arm64-gnu/libprotect_ffi.so',
        ],
        'linux-x64-gnu' => [
            'target/x86_64-unknown-linux-gnu/release/libprotect_ffi.so',
            'platforms/linux-x64-gnu/libprotect_ffi.so',
        ],
        'win32-x64-msvc' => [
            'target/x86_64-pc-windows-msvc/release/protect_ffi.dll',
            'platforms/win32-x64-msvc/protect_ffi.dll',
        ],
    ];

    /**
     * Get the library path for the current platform.
     *
     * @throws LoaderException
     */
    public static function getLibraryPath(): string
    {
        $rootDir = dirname(path: __DIR__, levels: 1);
        $platform = self::detectPlatform();
        $paths = self::$platforms[$platform];

        foreach ($paths as $relativePath) {
            $fullPath = "{$rootDir}/{$relativePath}";

            if (is_readable($fullPath)) {
                return $fullPath;
            }
        }

        throw LoaderException::nativeLibraryNotReadable($platform, (string) end($paths));
    }

    /**
     * Detect the current platform.
     *
     * @throws LoaderException
     */
    private static function detectPlatform(): string
    {
        $os = strtolower(PHP_OS_FAMILY);
        $arch = self::normalizeArchitecture(php_uname('m'));

        return self::normalizePlatform("{$os}-{$arch}");
    }

    /**
     * Normalize architecture names to a consistent format.
     */
    private static function normalizeArchitecture(string $arch): string
    {
        $arch = strtolower($arch);

        return match ($arch) {
            'arm64', 'aarch64' => 'arm64',
            'x86_64', 'amd64' => 'x64',
            default => $arch
        };
    }

    /**
     * Normalize platform string to supported platform identifier.
     *
     * @throws LoaderException When platform is not supported
     */
    private static function normalizePlatform(string $platform): string
    {
        return match ($platform) {
            'darwin-arm64' => 'darwin-arm64',
            'darwin-x64' => 'darwin-x64',
            'linux-arm64' => 'linux-arm64-gnu',
            'linux-x64' => 'linux-x64-gnu',
            'windows-x64' => 'win32-x64-msvc',
            default => throw LoaderException::unsupportedPlatform($platform)
        };
    }
}
