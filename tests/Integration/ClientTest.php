<?php

declare(strict_types=1);

namespace CipherStash\Protect\FFI\Tests\Integration;

use CipherStash\Protect\FFI\Client;
use CipherStash\Protect\FFI\Exceptions\FFIException;
use PHPUnit\Framework\TestCase;

class ClientTest extends TestCase
{
    private static string $config;

    public static function setUpBeforeClass(): void
    {
        $config = json_encode([
            'v' => 2,
            'tables' => [
                'users' => [
                    'email' => [
                        'cast_as' => 'text',
                        'indexes' => [
                            'unique' => (object) [],
                            'match' => (object) [],
                        ],
                    ],
                    'age' => [
                        'cast_as' => 'int',
                        'indexes' => [
                            'ore' => (object) [],
                        ],
                    ],
                    'job_title' => [
                        'cast_as' => 'text',
                        'indexes' => [
                            'match' => (object) [],
                        ],
                    ],
                    'metadata' => [
                        'cast_as' => 'jsonb',
                        'indexes' => [
                            'ste_vec' => [
                                'prefix' => 'users.metadata',
                            ],
                        ],
                    ],
                    'session' => [
                        'cast_as' => 'jsonb',
                        'indexes' => (object) [],
                    ],
                ],
            ],
        ], JSON_THROW_ON_ERROR);

        self::$config = $config;
    }

    protected function setUp(): void
    {
        parent::setUp();

        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('Integration testing is disabled on Windows due to known FFI segmentation faults.');
        }
    }

    public function test_new_client_with_valid_config(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        $this->assertInstanceOf(\FFI\CData::class, $clientPtr);

        $client->freeClient($clientPtr);
    }

    public function test_new_client_throws_exception_with_empty_config(): void
    {
        $client = new Client;

        $this->expectException(FFIException::class);

        $client->newClient('{}');
    }

    public function test_new_client_throws_exception_with_invalid_config(): void
    {
        $client = new Client;

        $this->expectException(FFIException::class);

        $client->newClient('invalid-config');
    }

    public function test_encrypt_decrypt_roundtrip(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        try {
            $plaintext = 'john@example.com';
            $encryptResultJson = $client->encrypt($clientPtr, $plaintext, 'email', 'users');

            $encryptResult = json_decode(json: $encryptResultJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($encryptResult);
            $this->assertArrayHasKey('k', $encryptResult);
            $this->assertSame('ct', $encryptResult['k']);
            $this->assertArrayHasKey('c', $encryptResult);
            $ciphertext = $encryptResult['c'];
            $this->assertIsString($ciphertext);
            $this->assertNotEmpty($ciphertext);
            $this->assertNotEquals($plaintext, $ciphertext);
            $this->assertArrayHasKey('dt', $encryptResult);
            $this->assertSame('text', $encryptResult['dt']);
            $this->assertArrayHasKey('i', $encryptResult);
            $identifier = $encryptResult['i'];
            $this->assertIsArray($identifier);
            $this->assertSame('users', $identifier['t']);
            $this->assertSame('email', $identifier['c']);

            $decryptResult = $client->decrypt($clientPtr, $ciphertext);
            $this->assertSame($plaintext, $decryptResult);
        } finally {
            $client->freeClient($clientPtr);
        }
    }

    public function test_encrypt_decrypt_complex_json_roundtrip(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        try {
            $complexJson = json_encode([
                'user_profile' => [
                    'customer_id' => 'CUST-20240315-7892',
                    'membership_tier' => 'premium',
                    'registration_date' => '2024-03-15T09:30:00Z',
                    'last_login' => '2024-06-15T14:22:33Z',
                    'preferences' => [
                        'language' => 'en-US',
                        'timezone' => 'America/New_York',
                        'notifications' => [
                            'email' => true,
                            'sms' => false,
                            'push' => true,
                        ],
                        'theme' => 'dark',
                    ],
                ],
                'billing_info' => [
                    'payment_methods' => [
                        [
                            'type' => 'credit_card',
                            'last_four' => '4532',
                            'brand' => 'visa',
                            'exp_month' => 12,
                            'exp_year' => 2027,
                        ],
                        [
                            'type' => 'bank_account',
                            'account_type' => 'checking',
                            'bank_name' => 'Example Community Bank',
                            'routing_last_four' => '0021',
                        ],
                    ],
                    'billing_address' => [
                        'street' => '742 Evergreen Terrace',
                        'city' => 'Springfield',
                        'state' => 'OR',
                        'postal_code' => '97477',
                        'country' => 'US',
                    ],
                    'tax_info' => [
                        'tax_id' => 'TIN-456-78-9012',
                        'tax_exempt' => false,
                        'business_type' => 'individual',
                    ],
                ],
                'activity_data' => [
                    'session_count' => 247,
                    'total_purchases' => 18,
                    'lifetime_value' => 2847.63,
                    'avg_session_duration' => 420,
                    'favorite_categories' => ['electronics', 'books', 'home-garden'],
                    'recent_searches' => [
                        'wireless headphones',
                        'ergonomic office chair',
                        'smart home devices',
                    ],
                    'device_info' => [
                        'primary_device' => 'desktop',
                        'os' => 'macOS 14.5',
                        'browser' => 'Safari 17.4',
                        'screen_resolution' => '2560x1440',
                    ],
                ],
                'system_metadata' => [
                    'record_version' => '1.2.4',
                    'data_classification' => 'confidential',
                    'retention_policy' => 'delete_after_7_years',
                    'compliance_flags' => [
                        'gdpr_compliant' => true,
                        'ccpa_compliant' => true,
                        'data_minimization' => true,
                    ],
                    'audit_info' => [
                        'created_by' => 'registration_system',
                        'created_at' => '2024-03-15T09:30:00Z',
                        'last_modified_by' => 'profile_update_service',
                        'last_modified_at' => '2024-06-10T16:45:22Z',
                        'modification_count' => 14,
                    ],
                    'integration_data' => [
                        'external_id' => 'ext_usr_7bf4c8d9e12a',
                        'sync_status' => 'synchronized',
                        'last_sync' => '2024-06-15T08:00:00Z',
                    ],
                    'test_fields' => [
                        'special_chars' => '!@#$%^&*()_+-=[]{}|;:,.<>?',
                        'unicode_text' => 'User speaks: English, Français, Español, 中文, العربية, Русский 🌐',
                        'null_value' => null,
                        'empty_string' => '',
                        'empty_array' => [],
                        'empty_object' => (object) [],
                        'boolean_flags' => [
                            'feature_a_enabled' => true,
                            'beta_tester' => false,
                            'email_verified' => true,
                        ],
                        'numeric_values' => [
                            'score' => 95.7,
                            'rank' => 1247,
                            'percentage' => 0.863,
                            'negative_value' => -42,
                            'zero_value' => 0,
                            'scientific_notation' => 1.23e-4,
                        ],
                    ],
                ],
            ], JSON_THROW_ON_ERROR);

            $encryptResultJson = $client->encrypt($clientPtr, $complexJson, 'metadata', 'users');

            $encryptResult = json_decode(json: $encryptResultJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($encryptResult);
            $this->assertArrayHasKey('k', $encryptResult);
            $this->assertSame('sv', $encryptResult['k']);
            $this->assertArrayHasKey('c', $encryptResult);
            $ciphertext = $encryptResult['c'];
            $this->assertIsString($ciphertext);
            $this->assertNotEmpty($ciphertext);
            $this->assertNotEquals($complexJson, $ciphertext);
            $this->assertArrayHasKey('dt', $encryptResult);
            $this->assertSame('jsonb', $encryptResult['dt']);
            $this->assertArrayHasKey('sv', $encryptResult);
            $this->assertIsArray($encryptResult['sv']);
            $this->assertNotEmpty($encryptResult['sv']);
            $this->assertArrayHasKey('i', $encryptResult);
            $identifier = $encryptResult['i'];
            $this->assertIsArray($identifier);
            $this->assertSame('users', $identifier['t']);
            $this->assertSame('metadata', $identifier['c']);

            $decryptResultJson = $client->decrypt($clientPtr, $ciphertext);

            $decryptResult = json_decode(json: $decryptResultJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $originalData = json_decode(json: $complexJson, associative: true, flags: JSON_THROW_ON_ERROR);

            $this->assertIsArray($decryptResult);
            $this->assertIsArray($originalData);

            $userProfile = $decryptResult['user_profile'];
            $this->assertIsArray($userProfile);
            $billingInfo = $decryptResult['billing_info'];
            $this->assertIsArray($billingInfo);
            $activityData = $decryptResult['activity_data'];
            $this->assertIsArray($activityData);
            $systemMetadata = $decryptResult['system_metadata'];
            $this->assertIsArray($systemMetadata);

            $this->assertSame('CUST-20240315-7892', $userProfile['customer_id']);
            $this->assertSame('premium', $userProfile['membership_tier']);
            $this->assertSame('2024-03-15T09:30:00Z', $userProfile['registration_date']);
            $this->assertSame('2024-06-15T14:22:33Z', $userProfile['last_login']);

            $preferences = $userProfile['preferences'];
            $this->assertIsArray($preferences);
            $this->assertSame('en-US', $preferences['language']);
            $this->assertSame('America/New_York', $preferences['timezone']);
            $this->assertSame('dark', $preferences['theme']);

            $notifications = $preferences['notifications'];
            $this->assertIsArray($notifications);
            $this->assertTrue($notifications['email']);
            $this->assertFalse($notifications['sms']);
            $this->assertTrue($notifications['push']);

            $paymentMethods = $billingInfo['payment_methods'];
            $this->assertIsArray($paymentMethods);
            $creditCard = $paymentMethods[0];
            $this->assertIsArray($creditCard);
            $bankAccount = $paymentMethods[1];
            $this->assertIsArray($bankAccount);
            $billingAddress = $billingInfo['billing_address'];
            $this->assertIsArray($billingAddress);
            $taxInfo = $billingInfo['tax_info'];
            $this->assertIsArray($taxInfo);

            $this->assertSame('credit_card', $creditCard['type']);
            $this->assertSame('4532', $creditCard['last_four']);
            $this->assertSame('visa', $creditCard['brand']);
            $this->assertSame(12, $creditCard['exp_month']);
            $this->assertSame(2027, $creditCard['exp_year']);
            $this->assertSame('bank_account', $bankAccount['type']);
            $this->assertSame('checking', $bankAccount['account_type']);
            $this->assertSame('Example Community Bank', $bankAccount['bank_name']);
            $this->assertSame('0021', $bankAccount['routing_last_four']);
            $this->assertSame('742 Evergreen Terrace', $billingAddress['street']);
            $this->assertSame('Springfield', $billingAddress['city']);
            $this->assertSame('OR', $billingAddress['state']);
            $this->assertSame('97477', $billingAddress['postal_code']);
            $this->assertSame('US', $billingAddress['country']);
            $this->assertSame('TIN-456-78-9012', $taxInfo['tax_id']);
            $this->assertFalse($taxInfo['tax_exempt']);
            $this->assertSame('individual', $taxInfo['business_type']);

            $this->assertSame(247, $activityData['session_count']);
            $this->assertSame(18, $activityData['total_purchases']);
            $this->assertSame(2847.63, $activityData['lifetime_value']);
            $this->assertSame(420, $activityData['avg_session_duration']);
            $this->assertEquals(['electronics', 'books', 'home-garden'], $activityData['favorite_categories']);

            $recentSearches = $activityData['recent_searches'];
            $this->assertIsArray($recentSearches);
            $this->assertSame('wireless headphones', $recentSearches[0]);
            $this->assertSame('ergonomic office chair', $recentSearches[1]);
            $this->assertSame('smart home devices', $recentSearches[2]);

            $deviceInfo = $activityData['device_info'];
            $this->assertIsArray($deviceInfo);
            $this->assertSame('desktop', $deviceInfo['primary_device']);
            $this->assertSame('macOS 14.5', $deviceInfo['os']);
            $this->assertSame('Safari 17.4', $deviceInfo['browser']);
            $this->assertSame('2560x1440', $deviceInfo['screen_resolution']);

            $this->assertSame('1.2.4', $systemMetadata['record_version']);
            $this->assertSame('confidential', $systemMetadata['data_classification']);
            $this->assertSame('delete_after_7_years', $systemMetadata['retention_policy']);

            $complianceFlags = $systemMetadata['compliance_flags'];
            $this->assertIsArray($complianceFlags);
            $this->assertTrue($complianceFlags['gdpr_compliant']);
            $this->assertTrue($complianceFlags['ccpa_compliant']);
            $this->assertTrue($complianceFlags['data_minimization']);

            $auditInfo = $systemMetadata['audit_info'];
            $this->assertIsArray($auditInfo);
            $this->assertSame('registration_system', $auditInfo['created_by']);
            $this->assertSame('2024-03-15T09:30:00Z', $auditInfo['created_at']);
            $this->assertSame('profile_update_service', $auditInfo['last_modified_by']);
            $this->assertSame('2024-06-10T16:45:22Z', $auditInfo['last_modified_at']);
            $this->assertSame(14, $auditInfo['modification_count']);

            $integrationData = $systemMetadata['integration_data'];
            $this->assertIsArray($integrationData);
            $this->assertSame('ext_usr_7bf4c8d9e12a', $integrationData['external_id']);
            $this->assertSame('synchronized', $integrationData['sync_status']);
            $this->assertSame('2024-06-15T08:00:00Z', $integrationData['last_sync']);

            $testFields = $systemMetadata['test_fields'];
            $this->assertIsArray($testFields);
            $this->assertSame('!@#$%^&*()_+-=[]{}|;:,.<>?', $testFields['special_chars']);
            $this->assertSame('User speaks: English, Français, Español, 中文, العربية, Русский 🌐', $testFields['unicode_text']);
            $this->assertNull($testFields['null_value']);
            $this->assertSame('', $testFields['empty_string']);
            $this->assertEquals([], $testFields['empty_array']);
            $this->assertEquals([], $testFields['empty_object']);

            $booleanFlags = $testFields['boolean_flags'];
            $this->assertIsArray($booleanFlags);
            $this->assertTrue($booleanFlags['feature_a_enabled']);
            $this->assertFalse($booleanFlags['beta_tester']);
            $this->assertTrue($booleanFlags['email_verified']);

            $numericValues = $testFields['numeric_values'];
            $this->assertIsArray($numericValues);
            $this->assertSame(95.7, $numericValues['score']);
            $this->assertSame(1247, $numericValues['rank']);
            $this->assertSame(0.863, $numericValues['percentage']);
            $this->assertSame(-42, $numericValues['negative_value']);
            $this->assertSame(0, $numericValues['zero_value']);
            $this->assertSame(1.23e-4, $numericValues['scientific_notation']);
        } finally {
            $client->freeClient($clientPtr);
        }
    }

    public function test_encrypt_decrypt_roundtrip_with_context(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        try {
            $plaintext = 'john@example.com';

            // Only testing 'tag' and 'value' context types because 'identity_claim' requires
            // CTS token authentication.
            $contextJson = json_encode([
                'tag' => ['pii', 'hipaa'],
                'value' => [
                    ['key' => 'tenant_id', 'value' => 'tenant_2ynTJf38e9HvuAO8jaX5kAyVaKI'],
                    ['key' => 'role', 'value' => 'admin'],
                ],
            ], JSON_THROW_ON_ERROR);

            $encryptResultJson = $client->encrypt($clientPtr, $plaintext, 'email', 'users', $contextJson);
            $encryptResult = json_decode(json: $encryptResultJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($encryptResult);
            $this->assertArrayHasKey('c', $encryptResult);

            $ciphertext = $encryptResult['c'];
            $this->assertIsString($ciphertext);
            $this->assertNotEmpty($ciphertext);
            $this->assertNotEquals($plaintext, $ciphertext);
            $this->assertArrayHasKey('dt', $encryptResult);
            $this->assertSame('text', $encryptResult['dt']);

            $decryptResult = $client->decrypt($clientPtr, $ciphertext, $contextJson);
            $this->assertSame($plaintext, $decryptResult);
        } finally {
            $client->freeClient($clientPtr);
        }
    }

    public function test_decrypt_throws_exception_with_wrong_tag_context(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        try {
            $plaintext = 'john@example.com';
            $originalContextJson = json_encode([
                'tag' => ['original-context'],
                'value' => [
                    ['key' => 'tenant_id', 'value' => 'original-tenant'],
                    ['key' => 'role', 'value' => 'original-role'],
                ],
            ], JSON_THROW_ON_ERROR);

            $encryptResultJson = $client->encrypt($clientPtr, $plaintext, 'email', 'users', $originalContextJson);
            $encryptResult = json_decode(json: $encryptResultJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($encryptResult);
            $ciphertext = $encryptResult['c'];
            $this->assertIsString($ciphertext);

            $wrongTagContextJson = json_encode([
                'tag' => ['wrong-context'],
                'value' => [
                    ['key' => 'tenant_id', 'value' => 'original-tenant'],
                    ['key' => 'role', 'value' => 'original-role'],
                ],
            ], JSON_THROW_ON_ERROR);
            $this->expectException(FFIException::class);
            $client->decrypt($clientPtr, $ciphertext, $wrongTagContextJson);
        } finally {
            $client->freeClient($clientPtr);
        }
    }

    public function test_decrypt_throws_exception_with_wrong_value_context(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        try {
            $plaintext = 'john@example.com';
            $originalContextJson = json_encode([
                'tag' => ['original-context'],
                'value' => [
                    ['key' => 'tenant_id', 'value' => 'original-tenant'],
                    ['key' => 'role', 'value' => 'original-role'],
                ],
            ], JSON_THROW_ON_ERROR);

            $encryptResultJson = $client->encrypt($clientPtr, $plaintext, 'email', 'users', $originalContextJson);
            $encryptResult = json_decode(json: $encryptResultJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($encryptResult);
            $ciphertext = $encryptResult['c'];
            $this->assertIsString($ciphertext);

            $wrongValueContextJson = json_encode([
                'tag' => ['original-context'],
                'value' => [
                    ['key' => 'tenant_id', 'value' => 'wrong-tenant'],
                    ['key' => 'role', 'value' => 'wrong-role'],
                ],
            ], JSON_THROW_ON_ERROR);
            $this->expectException(FFIException::class);
            $client->decrypt($clientPtr, $ciphertext, $wrongValueContextJson);
        } finally {
            $client->freeClient($clientPtr);
        }
    }

    public function test_encrypt_throws_exception_with_invalid_context(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        try {
            $this->expectException(FFIException::class);
            $client->encrypt($clientPtr, 'john@example.com', 'email', 'users', 'invalid-context');
        } finally {
            $client->freeClient($clientPtr);
        }
    }

    public function test_decrypt_throws_exception_with_invalid_ciphertext(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        try {
            $this->expectException(FFIException::class);
            $client->decrypt($clientPtr, 'invalid-ciphertext');
        } finally {
            $client->freeClient($clientPtr);
        }
    }

    public function test_decrypt_throws_exception_with_invalid_context(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        try {
            $plaintext = 'john@example.com';
            $contextJson = json_encode(['tag' => ['valid-context']], JSON_THROW_ON_ERROR);

            $encryptResultJson = $client->encrypt($clientPtr, $plaintext, 'email', 'users', $contextJson);
            $encryptResult = json_decode(json: $encryptResultJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($encryptResult);
            $ciphertext = $encryptResult['c'];
            $this->assertIsString($ciphertext);

            $this->expectException(FFIException::class);
            $client->decrypt($clientPtr, $ciphertext, 'invalid-context');
        } finally {
            $client->freeClient($clientPtr);
        }
    }

    public function test_encrypt_jsonb_returns_null_sv_on_non_ste_vec_column(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        try {
            $sessionData = '{"browser": "Safari 17.4", "ip": "123.456.7.8", "last_active": "2020-01-21T10:30:00Z"}';

            $encryptResultJson = $client->encrypt($clientPtr, $sessionData, 'session', 'users');
            $encryptResult = json_decode(json: $encryptResultJson, associative: true, flags: JSON_THROW_ON_ERROR);

            $this->assertIsArray($encryptResult);
            $this->assertSame('sv', $encryptResult['k']);
            $this->assertSame('jsonb', $encryptResult['dt']);
            $this->assertNull($encryptResult['sv']);
        } finally {
            $client->freeClient($clientPtr);
        }
    }

    public function test_decrypt_throws_exception_with_context_on_ste_vec_column(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        try {
            $plaintext = '{"city":"Boston","state":"MA"}';

            $contextJson = json_encode([
                'tag' => ['test-context'],
            ], JSON_THROW_ON_ERROR);

            // Context is ignored during encryption
            $encryptResultJson = $client->encrypt($clientPtr, $plaintext, 'metadata', 'users', $contextJson);
            $encryptResult = json_decode(json: $encryptResultJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($encryptResult);
            $this->assertArrayHasKey('c', $encryptResult);
            $ciphertext = $encryptResult['c'];
            $this->assertIsString($ciphertext);
            $this->assertNotEmpty($ciphertext);

            // Context causes decryption to fail
            $this->expectException(FFIException::class);
            $client->decrypt($clientPtr, $ciphertext, $contextJson);
        } finally {
            $client->freeClient($clientPtr);
        }
    }

    public function test_encrypt_decrypt_bulk_roundtrip(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        try {
            $items = [
                [
                    'plaintext' => 'john@example.com',
                    'column' => 'email',
                    'table' => 'users',
                ],
                [
                    'plaintext' => '29',
                    'column' => 'age',
                    'table' => 'users',
                ],
                [
                    'plaintext' => 'Software Engineer',
                    'column' => 'job_title',
                    'table' => 'users',
                ],
                [
                    'plaintext' => '{"city":"Boston","state":"MA"}',
                    'column' => 'metadata',
                    'table' => 'users',
                ],
            ];

            $itemsJson = json_encode($items, JSON_THROW_ON_ERROR);
            $encryptResultsJson = $client->encryptBulk($clientPtr, $itemsJson);
            $encryptResults = json_decode(json: $encryptResultsJson, associative: true, flags: JSON_THROW_ON_ERROR);

            $this->assertIsArray($encryptResults);
            $this->assertCount(4, $encryptResults);

            $emailResult = $encryptResults[0];
            $this->assertIsArray($emailResult);
            $this->assertArrayHasKey('k', $emailResult);
            $this->assertSame('ct', $emailResult['k']);
            $this->assertArrayHasKey('c', $emailResult);
            $this->assertIsString($emailResult['c']);
            $this->assertNotEmpty($emailResult['c']);
            $this->assertArrayHasKey('dt', $emailResult);
            $this->assertSame('text', $emailResult['dt']);
            $this->assertArrayHasKey('i', $emailResult);
            $emailIdentifier = $emailResult['i'];
            $this->assertIsArray($emailIdentifier);
            $this->assertSame('users', $emailIdentifier['t']);
            $this->assertSame('email', $emailIdentifier['c']);

            $ageResult = $encryptResults[1];
            $this->assertIsArray($ageResult);
            $this->assertArrayHasKey('k', $ageResult);
            $this->assertSame('ct', $ageResult['k']);
            $this->assertArrayHasKey('c', $ageResult);
            $this->assertIsString($ageResult['c']);
            $this->assertNotEmpty($ageResult['c']);
            $this->assertArrayHasKey('dt', $ageResult);
            $this->assertSame('int', $ageResult['dt']);
            $this->assertArrayHasKey('i', $ageResult);
            $ageIdentifier = $ageResult['i'];
            $this->assertIsArray($ageIdentifier);
            $this->assertSame('users', $ageIdentifier['t']);
            $this->assertSame('age', $ageIdentifier['c']);

            $jobTitleResult = $encryptResults[2];
            $this->assertIsArray($jobTitleResult);
            $this->assertArrayHasKey('k', $jobTitleResult);
            $this->assertSame('ct', $jobTitleResult['k']);
            $this->assertArrayHasKey('c', $jobTitleResult);
            $this->assertIsString($jobTitleResult['c']);
            $this->assertNotEmpty($jobTitleResult['c']);
            $this->assertArrayHasKey('dt', $jobTitleResult);
            $this->assertSame('text', $jobTitleResult['dt']);
            $this->assertArrayHasKey('i', $jobTitleResult);
            $jobTitleIdentifier = $jobTitleResult['i'];
            $this->assertIsArray($jobTitleIdentifier);
            $this->assertSame('users', $jobTitleIdentifier['t']);
            $this->assertSame('job_title', $jobTitleIdentifier['c']);

            $metadataResult = $encryptResults[3];
            $this->assertIsArray($metadataResult);
            $this->assertArrayHasKey('k', $metadataResult);
            $this->assertSame('sv', $metadataResult['k']);
            $this->assertArrayHasKey('c', $metadataResult);
            $this->assertIsString($metadataResult['c']);
            $this->assertNotEmpty($metadataResult['c']);
            $this->assertArrayHasKey('dt', $metadataResult);
            $this->assertSame('jsonb', $metadataResult['dt']);
            $this->assertArrayHasKey('sv', $metadataResult);
            $this->assertIsArray($metadataResult['sv']);
            $this->assertNotEmpty($metadataResult['sv']);

            foreach ($metadataResult['sv'] as $svEntry) {
                $this->assertIsArray($svEntry);
                $this->assertArrayHasKey('s', $svEntry);
                $this->assertArrayHasKey('t', $svEntry);
                $this->assertArrayHasKey('r', $svEntry);
                $this->assertArrayHasKey('pa', $svEntry);
                $this->assertIsString($svEntry['s']);
                $this->assertIsString($svEntry['t']);
                $this->assertIsString($svEntry['r']);
                $this->assertIsBool($svEntry['pa']);
                $this->assertNotEmpty($svEntry['s']);
                $this->assertNotEmpty($svEntry['t']);
                $this->assertNotEmpty($svEntry['r']);
            }

            $this->assertArrayHasKey('i', $metadataResult);
            $metadataIdentifier = $metadataResult['i'];
            $this->assertIsArray($metadataIdentifier);
            $this->assertSame('users', $metadataIdentifier['t']);
            $this->assertSame('metadata', $metadataIdentifier['c']);

            $ciphertexts = array_column($encryptResults, 'c');
            $this->assertCount(4, $ciphertexts);

            foreach ($ciphertexts as $ciphertext) {
                $this->assertIsString($ciphertext);
                $this->assertNotEmpty($ciphertext);
            }

            $encryptedItems = array_map(function ($ciphertext) {
                return ['ciphertext' => $ciphertext];
            }, $ciphertexts);

            $encryptedItemsJson = json_encode($encryptedItems, JSON_THROW_ON_ERROR);
            $decryptResultsJson = $client->decryptBulk($clientPtr, $encryptedItemsJson);
            $decryptResults = json_decode(json: $decryptResultsJson, associative: true, flags: JSON_THROW_ON_ERROR);

            $expectedPlaintexts = [
                'john@example.com',
                '29',
                'Software Engineer',
                '{"city":"Boston","state":"MA"}',
            ];

            $this->assertEquals($expectedPlaintexts, $decryptResults);
        } finally {
            $client->freeClient($clientPtr);
        }
    }

    public function test_encrypt_decrypt_bulk_roundtrip_with_context(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        try {
            $items = [
                [
                    'plaintext' => 'john@example.com',
                    'column' => 'email',
                    'table' => 'users',
                    'context' => ['tag' => ['test-context']],
                ],
                [
                    'plaintext' => '29',
                    'column' => 'age',
                    'table' => 'users',
                    'context' => ['tag' => ['test-context']],
                ],
                [
                    'plaintext' => 'Software Engineer',
                    'column' => 'job_title',
                    'table' => 'users',
                    'context' => ['tag' => ['test-context']],
                ],
                [
                    'plaintext' => '{"city":"Boston","state":"MA"}',
                    'column' => 'metadata',
                    'table' => 'users',
                ],
            ];

            $itemsJson = json_encode($items, JSON_THROW_ON_ERROR);
            $encryptResultsJson = $client->encryptBulk($clientPtr, $itemsJson);
            $encryptResults = json_decode(json: $encryptResultsJson, associative: true, flags: JSON_THROW_ON_ERROR);

            $this->assertIsArray($encryptResults);
            $this->assertCount(4, $encryptResults);

            $decryptItems = array_map(function ($item, $encryptResult) {
                $this->assertIsArray($encryptResult);

                $ciphertext = $encryptResult['c'];
                $this->assertIsString($ciphertext);
                $this->assertNotEmpty($ciphertext);

                $decryptItem = ['ciphertext' => $ciphertext];

                if (isset($item['context'])) {
                    $decryptItem['context'] = $item['context'];
                }

                return $decryptItem;
            }, $items, $encryptResults);

            $decryptItemsJson = json_encode($decryptItems, JSON_THROW_ON_ERROR);
            $decryptResultsJson = $client->decryptBulk($clientPtr, $decryptItemsJson);
            $decryptResults = json_decode(json: $decryptResultsJson, associative: true, flags: JSON_THROW_ON_ERROR);

            $expectedPlaintexts = [
                'john@example.com',
                '29',
                'Software Engineer',
                '{"city":"Boston","state":"MA"}',
            ];

            $this->assertEquals($expectedPlaintexts, $decryptResults);
        } finally {
            $client->freeClient($clientPtr);
        }
    }

    public function test_encrypt_bulk_throws_exception_with_invalid_items(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        try {
            $this->expectException(FFIException::class);
            $client->encryptBulk($clientPtr, 'invalid-items');
        } finally {
            $client->freeClient($clientPtr);
        }
    }

    public function test_decrypt_bulk_throws_exception_with_invalid_items(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        try {
            $this->expectException(FFIException::class);
            $client->decryptBulk($clientPtr, 'invalid-items');
        } finally {
            $client->freeClient($clientPtr);
        }
    }

    public function test_create_search_terms(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        try {
            $items = [
                [
                    'plaintext' => 'john@example.com',
                    'column' => 'email',
                    'table' => 'users',
                ],
                [
                    'plaintext' => '29',
                    'column' => 'age',
                    'table' => 'users',
                ],
                [
                    'plaintext' => 'Software Engineer',
                    'column' => 'job_title',
                    'table' => 'users',
                ],
                [
                    'plaintext' => '{"city":"Boston","state":"MA"}',
                    'column' => 'metadata',
                    'table' => 'users',
                ],
            ];

            $itemsJson = json_encode($items, JSON_THROW_ON_ERROR);
            $searchTermResultsJson = $client->createSearchTerms($clientPtr, $itemsJson);

            $searchTermResults = json_decode(json: $searchTermResultsJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($searchTermResults);
            $this->assertCount(4, $searchTermResults);

            $emailTerm = $searchTermResults[0];
            $this->assertIsArray($emailTerm);
            $this->assertNotNull($emailTerm['hm']);
            $this->assertNull($emailTerm['ob']);
            $this->assertNotNull($emailTerm['bf']);
            $this->assertArrayHasKey('i', $emailTerm);

            $ageTerm = $searchTermResults[1];
            $this->assertIsArray($ageTerm);
            $this->assertNull($ageTerm['hm']);
            $this->assertNotNull($ageTerm['ob']);
            $this->assertNull($ageTerm['bf']);
            $this->assertArrayHasKey('i', $ageTerm);

            $jobTitleTerm = $searchTermResults[2];
            $this->assertIsArray($jobTitleTerm);
            $this->assertNull($jobTitleTerm['hm']);
            $this->assertNull($jobTitleTerm['ob']);
            $this->assertNotNull($jobTitleTerm['bf']);
            $this->assertArrayHasKey('i', $jobTitleTerm);

            $metadataTerm = $searchTermResults[3];
            $this->assertIsArray($metadataTerm);
            $this->assertArrayHasKey('sv', $metadataTerm);
            $this->assertIsArray($metadataTerm['sv']);
            $this->assertNotEmpty($metadataTerm['sv']);
            $this->assertArrayHasKey('i', $metadataTerm);

            foreach ($searchTermResults as $searchTerm) {
                $this->assertIsArray($searchTerm);
                $identifier = $searchTerm['i'];
                $this->assertIsArray($identifier);
                $this->assertSame('users', $identifier['t']);
                $this->assertContains($identifier['c'], ['email', 'age', 'job_title', 'metadata']);
            }
        } finally {
            $client->freeClient($clientPtr);
        }
    }

    public function test_create_search_terms_with_context(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        try {
            $items = [
                [
                    'plaintext' => 'john@example.com',
                    'column' => 'email',
                    'table' => 'users',
                    'context' => ['tag' => ['test-context']],
                ],
            ];

            $itemsJson = json_encode($items, JSON_THROW_ON_ERROR);
            $searchTermResultsJson = $client->createSearchTerms($clientPtr, $itemsJson);

            $searchTermResults = json_decode(json: $searchTermResultsJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($searchTermResults);
            $this->assertCount(1, $searchTermResults);

            $searchTerm = $searchTermResults[0];
            $this->assertIsArray($searchTerm);
            $this->assertNotNull($searchTerm['hm']);
            $this->assertNull($searchTerm['ob']);
            $this->assertNotNull($searchTerm['bf']);
            $this->assertArrayHasKey('i', $searchTerm);

            $identifier = $searchTerm['i'];
            $this->assertIsArray($identifier);
            $this->assertSame('users', $identifier['t']);
            $this->assertSame('email', $identifier['c']);
        } finally {
            $client->freeClient($clientPtr);
        }
    }

    public function test_create_search_terms_throws_exception_with_invalid_terms(): void
    {
        $client = new Client;
        $clientPtr = $client->newClient(self::$config);

        try {
            $this->expectException(FFIException::class);
            $client->createSearchTerms($clientPtr, 'invalid-terms');
        } finally {
            $client->freeClient($clientPtr);
        }
    }
}
