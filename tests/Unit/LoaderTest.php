<?php

declare(strict_types=1);

namespace CipherStash\Protect\FFI\Tests\Unit;

use CipherStash\Protect\FFI\Exceptions\LoaderException;
use CipherStash\Protect\FFI\Loader;
use PHPUnit\Framework\TestCase;

class LoaderTest extends TestCase
{
    public function test_get_library_path_returns_valid_path(): void
    {
        $path = Loader::getLibraryPath();

        $this->assertNotEmpty($path);
        $this->assertFileExists($path);
        $this->assertFileIsReadable($path);
    }

    public function test_get_library_path_throws_exception_for_missing_library(): void
    {
        $reflection = new \ReflectionClass(Loader::class);
        $platformsProperty = $reflection->getProperty('platforms');
        $platformsProperty->setAccessible(true);

        /** @var array<string, array<string>> $originalPlatforms */
        $originalPlatforms = $platformsProperty->getValue();

        $modifiedPlatforms = [];

        foreach ($originalPlatforms as $platform => $paths) {
            $modifiedPlatforms[$platform] = [
                'non-existent/path/to/library.so',
                'another-non-existent/path/to/library.so',
            ];
        }

        try {
            $platformsProperty->setValue(objectOrValue: null, value: $modifiedPlatforms);
            $this->expectException(LoaderException::class);

            Loader::getLibraryPath();
        } finally {
            $platformsProperty->setValue(objectOrValue: null, value: $originalPlatforms);
        }
    }

    public function test_detect_platform_returns_supported_platform(): void
    {
        $reflection = new \ReflectionClass(Loader::class);
        $method = $reflection->getMethod('detectPlatform');
        $method->setAccessible(true);

        $platform = $method->invoke(null);
        $platformsProperty = $reflection->getProperty('platforms');
        $platformsProperty->setAccessible(true);
        $platforms = $platformsProperty->getValue();

        $this->assertIsString($platform);
        $this->assertIsArray($platforms);
        $this->assertArrayHasKey($platform, $platforms);
    }

    /**
     * @dataProvider architectureNormalizationProvider
     */
    public function test_normalize_architecture_handles_variants(string $input, string $expected): void
    {
        $reflection = new \ReflectionClass(Loader::class);
        $method = $reflection->getMethod('normalizeArchitecture');
        $method->setAccessible(true);

        $this->assertEquals($expected, $method->invoke(null, $input));
    }

    /**
     * @dataProvider platformNormalizationProvider
     */
    public function test_normalize_platform_handles_supported_platforms(string $input, string $expected): void
    {
        $reflection = new \ReflectionClass(Loader::class);
        $method = $reflection->getMethod('normalizePlatform');
        $method->setAccessible(true);

        $this->assertEquals($expected, $method->invoke(null, $input));
    }

    public function test_normalize_platform_throws_exception_for_unsupported_platform(): void
    {
        $reflection = new \ReflectionClass(Loader::class);
        $method = $reflection->getMethod('normalizePlatform');
        $method->setAccessible(true);

        $this->expectException(LoaderException::class);
        $method->invoke(null, 'unsupported-platform');
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function architectureNormalizationProvider(): array
    {
        return [
            'arm64 stays arm64' => ['arm64', 'arm64'],
            'aarch64 becomes arm64' => ['aarch64', 'arm64'],
            'x86_64 becomes x64' => ['x86_64', 'x64'],
            'amd64 becomes x64' => ['amd64', 'x64'],
            'AMD64 becomes x64' => ['AMD64', 'x64'],
            'unknown stays unknown' => ['unknown', 'unknown'],
        ];
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function platformNormalizationProvider(): array
    {
        return [
            'darwin-arm64 maps correctly' => ['darwin-arm64', 'darwin-arm64'],
            'darwin-x64 maps correctly' => ['darwin-x64', 'darwin-x64'],
            'linux-arm64 maps to gnu variant' => ['linux-arm64', 'linux-arm64-gnu'],
            'linux-x64 maps to gnu variant' => ['linux-x64', 'linux-x64-gnu'],
            'windows-x64 maps to msvc variant' => ['windows-x64', 'win32-x64-msvc'],
        ];
    }
}
