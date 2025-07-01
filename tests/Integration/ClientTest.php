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
                                'prefix' => 'users/metadata',
                            ],
                        ],
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
            $resultJson = $client->encrypt($clientPtr, $plaintext, 'email', 'users');

            $this->assertNotEquals($plaintext, $resultJson);

            $result = json_decode(json: $resultJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($result);
            $this->assertArrayHasKey('k', $result);
            $this->assertEquals('ct', $result['k']);
            $this->assertArrayHasKey('c', $result);
            $this->assertIsString($result['c']);
            $this->assertNotEmpty($result['c']);
            $this->assertArrayHasKey('dt', $result);
            $this->assertEquals('text', $result['dt']);
            $this->assertArrayHasKey('i', $result);
            $identifier = $result['i'];
            $this->assertIsArray($identifier);
            $this->assertEquals('users', $identifier['t']);
            $this->assertEquals('email', $identifier['c']);

            $ciphertext = $result['c'];
            $decrypted = $client->decrypt($clientPtr, $ciphertext);
            $this->assertEquals($plaintext, $decrypted);
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

            $resultJson = $client->encrypt($clientPtr, $complexJson, 'metadata', 'users');

            $this->assertNotEquals($complexJson, $resultJson);

            $result = json_decode(json: $resultJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($result);
            $this->assertArrayHasKey('k', $result);
            $this->assertEquals('sv', $result['k']);
            $this->assertArrayHasKey('c', $result);
            $this->assertIsString($result['c']);
            $this->assertNotEmpty($result['c']);
            $this->assertArrayHasKey('dt', $result);
            $this->assertEquals('jsonb', $result['dt']);
            $this->assertArrayHasKey('sv', $result);
            $this->assertIsArray($result['sv']);
            $this->assertNotEmpty($result['sv']);
            $this->assertArrayHasKey('i', $result);
            $identifier = $result['i'];
            $this->assertIsArray($identifier);
            $this->assertEquals('users', $identifier['t']);
            $this->assertEquals('metadata', $identifier['c']);

            $ciphertext = $result['c'];
            $decrypted = $client->decrypt($clientPtr, $ciphertext);

            $decryptedData = json_decode(json: $decrypted, associative: true, flags: JSON_THROW_ON_ERROR);
            $originalData = json_decode(json: $complexJson, associative: true, flags: JSON_THROW_ON_ERROR);

            $this->assertIsArray($decryptedData);
            $this->assertIsArray($originalData);

            $userProfile = $decryptedData['user_profile'];
            $this->assertIsArray($userProfile);
            $billingInfo = $decryptedData['billing_info'];
            $this->assertIsArray($billingInfo);
            $activityData = $decryptedData['activity_data'];
            $this->assertIsArray($activityData);
            $systemMetadata = $decryptedData['system_metadata'];
            $this->assertIsArray($systemMetadata);

            $this->assertEquals('CUST-20240315-7892', $userProfile['customer_id']);
            $this->assertEquals('premium', $userProfile['membership_tier']);
            $this->assertEquals('2024-03-15T09:30:00Z', $userProfile['registration_date']);
            $this->assertEquals('2024-06-15T14:22:33Z', $userProfile['last_login']);

            $preferences = $userProfile['preferences'];
            $this->assertIsArray($preferences);
            $this->assertEquals('en-US', $preferences['language']);
            $this->assertEquals('America/New_York', $preferences['timezone']);
            $this->assertEquals('dark', $preferences['theme']);

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

            $this->assertEquals('credit_card', $creditCard['type']);
            $this->assertEquals('4532', $creditCard['last_four']);
            $this->assertEquals('visa', $creditCard['brand']);
            $this->assertEquals(12, $creditCard['exp_month']);
            $this->assertEquals(2027, $creditCard['exp_year']);
            $this->assertEquals('bank_account', $bankAccount['type']);
            $this->assertEquals('checking', $bankAccount['account_type']);
            $this->assertEquals('Example Community Bank', $bankAccount['bank_name']);
            $this->assertEquals('0021', $bankAccount['routing_last_four']);
            $this->assertEquals('742 Evergreen Terrace', $billingAddress['street']);
            $this->assertEquals('Springfield', $billingAddress['city']);
            $this->assertEquals('OR', $billingAddress['state']);
            $this->assertEquals('97477', $billingAddress['postal_code']);
            $this->assertEquals('US', $billingAddress['country']);
            $this->assertEquals('TIN-456-78-9012', $taxInfo['tax_id']);
            $this->assertFalse($taxInfo['tax_exempt']);
            $this->assertEquals('individual', $taxInfo['business_type']);

            $this->assertEquals(247, $activityData['session_count']);
            $this->assertEquals(18, $activityData['total_purchases']);
            $this->assertEquals(2847.63, $activityData['lifetime_value']);
            $this->assertEquals(420, $activityData['avg_session_duration']);
            $this->assertEquals(['electronics', 'books', 'home-garden'], $activityData['favorite_categories']);

            $recentSearches = $activityData['recent_searches'];
            $this->assertIsArray($recentSearches);
            $this->assertEquals('wireless headphones', $recentSearches[0]);
            $this->assertEquals('ergonomic office chair', $recentSearches[1]);
            $this->assertEquals('smart home devices', $recentSearches[2]);

            $deviceInfo = $activityData['device_info'];
            $this->assertIsArray($deviceInfo);
            $this->assertEquals('desktop', $deviceInfo['primary_device']);
            $this->assertEquals('macOS 14.5', $deviceInfo['os']);
            $this->assertEquals('Safari 17.4', $deviceInfo['browser']);
            $this->assertEquals('2560x1440', $deviceInfo['screen_resolution']);

            $this->assertEquals('1.2.4', $systemMetadata['record_version']);
            $this->assertEquals('confidential', $systemMetadata['data_classification']);
            $this->assertEquals('delete_after_7_years', $systemMetadata['retention_policy']);

            $complianceFlags = $systemMetadata['compliance_flags'];
            $this->assertIsArray($complianceFlags);
            $this->assertTrue($complianceFlags['gdpr_compliant']);
            $this->assertTrue($complianceFlags['ccpa_compliant']);
            $this->assertTrue($complianceFlags['data_minimization']);

            $auditInfo = $systemMetadata['audit_info'];
            $this->assertIsArray($auditInfo);
            $this->assertEquals('registration_system', $auditInfo['created_by']);
            $this->assertEquals('2024-03-15T09:30:00Z', $auditInfo['created_at']);
            $this->assertEquals('profile_update_service', $auditInfo['last_modified_by']);
            $this->assertEquals('2024-06-10T16:45:22Z', $auditInfo['last_modified_at']);
            $this->assertEquals(14, $auditInfo['modification_count']);

            $integrationData = $systemMetadata['integration_data'];
            $this->assertIsArray($integrationData);
            $this->assertEquals('ext_usr_7bf4c8d9e12a', $integrationData['external_id']);
            $this->assertEquals('synchronized', $integrationData['sync_status']);
            $this->assertEquals('2024-06-15T08:00:00Z', $integrationData['last_sync']);

            $testFields = $systemMetadata['test_fields'];
            $this->assertIsArray($testFields);
            $this->assertEquals('!@#$%^&*()_+-=[]{}|;:,.<>?', $testFields['special_chars']);
            $this->assertEquals('User speaks: English, Français, Español, 中文, العربية, Русский 🌐', $testFields['unicode_text']);
            $this->assertNull($testFields['null_value']);
            $this->assertEquals('', $testFields['empty_string']);
            $this->assertEquals([], $testFields['empty_array']);
            $this->assertEquals([], $testFields['empty_object']);

            $booleanFlags = $testFields['boolean_flags'];
            $this->assertIsArray($booleanFlags);
            $this->assertTrue($booleanFlags['feature_a_enabled']);
            $this->assertFalse($booleanFlags['beta_tester']);
            $this->assertTrue($booleanFlags['email_verified']);

            $numericValues = $testFields['numeric_values'];
            $this->assertIsArray($numericValues);
            $this->assertEquals(95.7, $numericValues['score']);
            $this->assertEquals(1247, $numericValues['rank']);
            $this->assertEquals(0.863, $numericValues['percentage']);
            $this->assertEquals(-42, $numericValues['negative_value']);
            $this->assertEquals(0, $numericValues['zero_value']);
            $this->assertEquals(1.23e-4, $numericValues['scientific_notation']);
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

            $resultJson = $client->encrypt($clientPtr, $plaintext, 'email', 'users', $contextJson);
            $this->assertNotEquals($plaintext, $resultJson);

            $result = json_decode(json: $resultJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($result);
            $this->assertArrayHasKey('c', $result);

            $ciphertext = $result['c'];
            $this->assertIsString($ciphertext);
            $this->assertNotEmpty($ciphertext);
            $this->assertArrayHasKey('dt', $result);
            $this->assertEquals('text', $result['dt']);

            $decrypted = $client->decrypt($clientPtr, $ciphertext, $contextJson);
            $this->assertEquals($plaintext, $decrypted);
        } finally {
            $client->freeClient($clientPtr);
        }
    }

    public function test_decrypt_fails_with_wrong_tag_context(): void
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

            $resultJson = $client->encrypt($clientPtr, $plaintext, 'email', 'users', $originalContextJson);
            $result = json_decode(json: $resultJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($result);
            $ciphertext = $result['c'];
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

    public function test_decrypt_fails_with_wrong_value_context(): void
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

            $resultJson = $client->encrypt($clientPtr, $plaintext, 'email', 'users', $originalContextJson);
            $result = json_decode(json: $resultJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($result);
            $ciphertext = $result['c'];
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

            $resultJson = $client->encrypt($clientPtr, $plaintext, 'email', 'users', $contextJson);
            $result = json_decode(json: $resultJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($result);
            $ciphertext = $result['c'];
            $this->assertIsString($ciphertext);

            $this->expectException(FFIException::class);
            $client->decrypt($clientPtr, $ciphertext, 'invalid-context');
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
            $resultJson = $client->encryptBulk($clientPtr, $itemsJson);
            $result = json_decode(json: $resultJson, associative: true, flags: JSON_THROW_ON_ERROR);

            $this->assertIsArray($result);
            $this->assertCount(4, $result);

            $emailResult = $result[0];
            $this->assertIsArray($emailResult);
            $this->assertArrayHasKey('k', $emailResult);
            $this->assertEquals('ct', $emailResult['k']);
            $this->assertArrayHasKey('c', $emailResult);
            $this->assertIsString($emailResult['c']);
            $this->assertNotEmpty($emailResult['c']);
            $this->assertArrayHasKey('dt', $emailResult);
            $this->assertEquals('text', $emailResult['dt']);
            $this->assertArrayHasKey('i', $emailResult);
            $emailIdentifier = $emailResult['i'];
            $this->assertIsArray($emailIdentifier);
            $this->assertEquals('users', $emailIdentifier['t']);
            $this->assertEquals('email', $emailIdentifier['c']);

            $ageResult = $result[1];
            $this->assertIsArray($ageResult);
            $this->assertArrayHasKey('k', $ageResult);
            $this->assertEquals('ct', $ageResult['k']);
            $this->assertArrayHasKey('c', $ageResult);
            $this->assertIsString($ageResult['c']);
            $this->assertNotEmpty($ageResult['c']);
            $this->assertArrayHasKey('dt', $ageResult);
            $this->assertEquals('int', $ageResult['dt']);
            $this->assertArrayHasKey('i', $ageResult);
            $ageIdentifier = $ageResult['i'];
            $this->assertIsArray($ageIdentifier);
            $this->assertEquals('users', $ageIdentifier['t']);
            $this->assertEquals('age', $ageIdentifier['c']);

            $jobTitleResult = $result[2];
            $this->assertIsArray($jobTitleResult);
            $this->assertArrayHasKey('k', $jobTitleResult);
            $this->assertEquals('ct', $jobTitleResult['k']);
            $this->assertArrayHasKey('c', $jobTitleResult);
            $this->assertIsString($jobTitleResult['c']);
            $this->assertNotEmpty($jobTitleResult['c']);
            $this->assertArrayHasKey('dt', $jobTitleResult);
            $this->assertEquals('text', $jobTitleResult['dt']);
            $this->assertArrayHasKey('i', $jobTitleResult);
            $jobTitleIdentifier = $jobTitleResult['i'];
            $this->assertIsArray($jobTitleIdentifier);
            $this->assertEquals('users', $jobTitleIdentifier['t']);
            $this->assertEquals('job_title', $jobTitleIdentifier['c']);

            $metadataResult = $result[3];
            $this->assertIsArray($metadataResult);
            $this->assertArrayHasKey('k', $metadataResult);
            $this->assertEquals('sv', $metadataResult['k']);
            $this->assertArrayHasKey('c', $metadataResult);
            $this->assertIsString($metadataResult['c']);
            $this->assertNotEmpty($metadataResult['c']);
            $this->assertArrayHasKey('dt', $metadataResult);
            $this->assertEquals('jsonb', $metadataResult['dt']);
            $this->assertArrayHasKey('sv', $metadataResult);
            $this->assertIsArray($metadataResult['sv']);
            $this->assertNotEmpty($metadataResult['sv']);

            foreach ($metadataResult['sv'] as $svEntry) {
                $this->assertIsArray($svEntry);
                $this->assertArrayHasKey('tokenized_selector', $svEntry);
                $this->assertArrayHasKey('term', $svEntry);
                $this->assertArrayHasKey('record', $svEntry);
                $this->assertArrayHasKey('parent_is_array', $svEntry);
                $this->assertIsString($svEntry['tokenized_selector']);
                $this->assertIsString($svEntry['term']);
                $this->assertIsString($svEntry['record']);
                $this->assertIsBool($svEntry['parent_is_array']);
                $this->assertNotEmpty($svEntry['tokenized_selector']);
                $this->assertNotEmpty($svEntry['term']);
                $this->assertNotEmpty($svEntry['record']);
            }

            $this->assertArrayHasKey('i', $metadataResult);
            $metadataIdentifier = $metadataResult['i'];
            $this->assertIsArray($metadataIdentifier);
            $this->assertEquals('users', $metadataIdentifier['t']);
            $this->assertEquals('metadata', $metadataIdentifier['c']);

            $ciphertexts = array_column($result, 'c');
            $this->assertCount(4, $ciphertexts);

            foreach ($ciphertexts as $ciphertext) {
                $this->assertIsString($ciphertext);
                $this->assertNotEmpty($ciphertext);
            }

            $encryptedItems = array_map(function ($ciphertext) {
                return ['ciphertext' => $ciphertext];
            }, $ciphertexts);

            $encryptedItemsJson = json_encode($encryptedItems, JSON_THROW_ON_ERROR);
            $decryptedResultJson = $client->decryptBulk($clientPtr, $encryptedItemsJson);
            $decryptedPlaintexts = json_decode(json: $decryptedResultJson, associative: true, flags: JSON_THROW_ON_ERROR);

            $expectedPlaintexts = [
                'john@example.com',
                '29',
                'Software Engineer',
                '{"city":"Boston","state":"MA"}',
            ];
            $this->assertEquals($expectedPlaintexts, $decryptedPlaintexts);
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
            $terms = [
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

            $termsJson = json_encode($terms, JSON_THROW_ON_ERROR);
            $resultJson = $client->createSearchTerms($clientPtr, $termsJson);

            $result = json_decode(json: $resultJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($result);
            $this->assertCount(4, $result);

            $emailTerm = $result[0];
            $this->assertIsArray($emailTerm);
            $this->assertNotNull($emailTerm['hm']);
            $this->assertNull($emailTerm['ob']);
            $this->assertNotNull($emailTerm['bf']);
            $this->assertArrayHasKey('i', $emailTerm);

            $ageTerm = $result[1];
            $this->assertIsArray($ageTerm);
            $this->assertNull($ageTerm['hm']);
            $this->assertNotNull($ageTerm['ob']);
            $this->assertNull($ageTerm['bf']);
            $this->assertArrayHasKey('i', $ageTerm);

            $jobTitleTerm = $result[2];
            $this->assertIsArray($jobTitleTerm);
            $this->assertNull($jobTitleTerm['hm']);
            $this->assertNull($jobTitleTerm['ob']);
            $this->assertNotNull($jobTitleTerm['bf']);
            $this->assertArrayHasKey('i', $jobTitleTerm);

            $metadataTerm = $result[3];
            $this->assertIsArray($metadataTerm);
            $this->assertArrayHasKey('sv', $metadataTerm);
            $this->assertIsArray($metadataTerm['sv']);
            $this->assertNotEmpty($metadataTerm['sv']);
            $this->assertArrayHasKey('i', $metadataTerm);

            foreach ($result as $searchTerm) {
                $this->assertIsArray($searchTerm);
                $identifier = $searchTerm['i'];
                $this->assertIsArray($identifier);
                $this->assertEquals('users', $identifier['t']);
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
            $terms = [
                [
                    'plaintext' => 'john@example.com',
                    'column' => 'email',
                    'table' => 'users',
                    'context' => ['tag' => ['test-context']],
                ],
            ];

            $termsJson = json_encode($terms, JSON_THROW_ON_ERROR);
            $resultJson = $client->createSearchTerms($clientPtr, $termsJson);

            $result = json_decode(json: $resultJson, associative: true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($result);
            $this->assertCount(1, $result);

            $searchTerm = $result[0];
            $this->assertIsArray($searchTerm);
            $this->assertNotNull($searchTerm['hm']);
            $this->assertNull($searchTerm['ob']);
            $this->assertNotNull($searchTerm['bf']);
            $this->assertArrayHasKey('i', $searchTerm);

            $identifier = $searchTerm['i'];
            $this->assertIsArray($identifier);
            $this->assertEquals('users', $identifier['t']);
            $this->assertEquals('email', $identifier['c']);
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
