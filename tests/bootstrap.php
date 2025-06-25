<?php

declare(strict_types=1);

use CipherStash\Protect\FFI\Exceptions\LoaderException;
use CipherStash\Protect\FFI\Loader;

/**
 * Display information about the native library being used.
 */
function displayLibraryInfo(): void
{
    try {
        $libraryPath = Loader::getLibraryPath();
        $isPrebuiltLibrary = str_contains($libraryPath, '/platforms/');
        $libraryType = $isPrebuiltLibrary ? 'prebuilt' : 'local';

        $green = "\033[0;32m";
        $nc = "\033[0m";

        $relativePath = str_replace(dirname(__DIR__).'/', './', $libraryPath);

        echo "\n🦀 Using {$libraryType} library: {$green}{$relativePath}{$nc}\n\n";
    } catch (LoaderException $e) {
        echo "\n❌ Could not determine native library type: [{$e->getMessage()}]\n\n";
    }
}

/**
 * Load environment variables from .env file into the environment.
 */
function loadEnvironmentVariables(): void
{
    $envFilePath = dirname(__DIR__).'/.env';

    if (! is_readable($envFilePath)) {
        return;
    }

    $lines = file($envFilePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        return;
    }

    foreach ($lines as $line) {
        $line = trim($line);

        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }

        $pos = strpos($line, '=');

        if ($pos === false) {
            continue;
        }

        $key = trim(substr($line, 0, $pos));
        $value = trim(substr($line, $pos + 1));

        if ($key !== '') {
            putenv("{$key}={$value}");
        }
    }
}

$loadEnvFile = $_ENV['TEST_LOAD_ENV_FILE'] ?? getenv('TEST_LOAD_ENV_FILE') ?: false;

if (filter_var($loadEnvFile, FILTER_VALIDATE_BOOLEAN)) {
    displayLibraryInfo();
    loadEnvironmentVariables();
}
