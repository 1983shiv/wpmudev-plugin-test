<?php
/**
 * Test Drive_API Credentials Functionality
 *
 * @package WpmudevPluginTest
 */

// Ensure WP_UnitTestCase is available
// require_once getenv( 'WP_TESTS_DIR' ) . '/includes/bootstrap.php';
require_once dirname( __FILE__ ) . '/bootstrap.php';

use WPMUDEV\PluginTest\Endpoints\V1\Drive_API;

class Test_Drive_API_Credentials extends WP_UnitTestCase {

    /**
     * Drive API instance
     *
     * @var Drive_API
     */
    private $drive_api;

    /**
     * Administrator user ID
     *
     * @var int
     */
    private $admin_user_id;

    /**
     * Editor user ID
     *
     * @var int
     */
    private $editor_user_id;

    /**
     * Set up test environment
     */
    public function setUp(): void {
        parent::setUp();

        $this->drive_api = new Drive_API();
        $this->drive_api->init();

        // Create test users
        $this->admin_user_id = $this->factory->user->create( array(
            'role' => 'administrator',
        ) );

        $this->editor_user_id = $this->factory->user->create( array(
            'role' => 'editor',
        ) );

        // Clean up any existing credentials
        delete_option( 'wpmudev_drive_credentials' );
    }

    /**
     * Clean up after tests
     */
    public function tearDown(): void {
        delete_option( 'wpmudev_drive_credentials' );
        delete_transient( 'wpmudev_drive_credential_log' );
        parent::tearDown();
    }

    /**
     * Test successful credentials save
     */
    public function test_save_credentials_success() {
        wp_set_current_user( $this->admin_user_id );

        $request = new WP_REST_Request( 'POST', '/wpmudev/v1/drive/save-credentials' );
        $request->set_param( 'client_id', '123456789-abcdefghijk.apps.googleusercontent.com' );
        $request->set_param( 'client_secret', 'valid_client_secret_123456789' );

        $response = rest_get_server()->dispatch( $request );
        $data = $response->get_data();

        $this->assertEquals( 200, $response->get_status() );
        $this->assertTrue( $data['success'] );
        $this->assertStringContainsString( 'successfully', $data['message'] );
        $this->assertTrue( $data['data']['has_credentials'] );
    }

    /**
     * Test save credentials with missing client ID
     */
    public function test_save_credentials_missing_client_id() {
        wp_set_current_user( $this->admin_user_id );

        $request = new WP_REST_Request( 'POST', '/wpmudev/v1/drive/save-credentials' );
        $request->set_param( 'client_secret', 'valid_client_secret_123456789' );

        $response = rest_get_server()->dispatch( $request );
        $data = $response->get_data();

        $this->assertEquals( 400, $response->get_status() );
        $this->assertEquals( 'missing_credentials', $data['code'] );
    }

    /**
     * Test save credentials with invalid client ID format
     */
    public function test_save_credentials_invalid_client_id() {
        wp_set_current_user( $this->admin_user_id );

        $request = new WP_REST_Request( 'POST', '/wpmudev/v1/drive/save-credentials' );
        $request->set_param( 'client_id', 'invalid_client_id' );
        $request->set_param( 'client_secret', 'valid_client_secret_123456789' );

        $response = rest_get_server()->dispatch( $request );
        $data = $response->get_data();

        $this->assertEquals( 400, $response->get_status() );
        $this->assertEquals( 'invalid_client_id', $data['code'] );
    }

    /**
     * Test permission check for non-admin user
     */
    public function test_save_credentials_permission_denied() {
        wp_set_current_user( $this->editor_user_id );

        $request = new WP_REST_Request( 'POST', '/wpmudev/v1/drive/save-credentials' );
        $request->set_param( 'client_id', '123456789-abcdefghijk.apps.googleusercontent.com' );
        $request->set_param( 'client_secret', 'valid_client_secret_123456789' );

        $response = rest_get_server()->dispatch( $request );

        $this->assertEquals( 403, $response->get_status() );
    }

    /**
     * Test get credentials when none exist
     */
    public function test_get_credentials_none_exist() {
        wp_set_current_user( $this->admin_user_id );

        $request = new WP_REST_Request( 'GET', '/wpmudev/v1/drive/get-credentials' );
        $response = rest_get_server()->dispatch( $request );
        $data = $response->get_data();

        $this->assertEquals( 200, $response->get_status() );
        $this->assertTrue( $data['success'] );
        $this->assertFalse( $data['has_credentials'] );
        $this->assertNull( $data['data'] );
    }

    /**
     * Test get credentials after saving
     */
    public function test_get_credentials_after_save() {
        wp_set_current_user( $this->admin_user_id );

        // First save credentials
        $save_request = new WP_REST_Request( 'POST', '/wpmudev/v1/drive/save-credentials' );
        $save_request->set_param( 'client_id', '123456789-abcdefghijk.apps.googleusercontent.com' );
        $save_request->set_param( 'client_secret', 'valid_client_secret_123456789' );
        rest_get_server()->dispatch( $save_request );

        // Then get credentials
        $get_request = new WP_REST_Request( 'GET', '/wpmudev/v1/drive/get-credentials' );
        $response = rest_get_server()->dispatch( $get_request );
        $data = $response->get_data();

        $this->assertEquals( 200, $response->get_status() );
        $this->assertTrue( $data['success'] );
        $this->assertTrue( $data['has_credentials'] );
        $this->assertStringContainsString( '123456789...', $data['data']['client_id'] );
        $this->assertArrayHasKey( 'created_at', $data['data'] );
    }

    /**
     * Test encryption and decryption of credentials
     */
    public function test_credentials_encryption() {
        wp_set_current_user( $this->admin_user_id );

        $client_id = '123456789-abcdefghijk.apps.googleusercontent.com';
        $client_secret = 'valid_client_secret_123456789';

        // Save credentials
        $request = new WP_REST_Request( 'POST', '/wpmudev/v1/drive/save-credentials' );
        $request->set_param( 'client_id', $client_id );
        $request->set_param( 'client_secret', $client_secret );
        rest_get_server()->dispatch( $request );

        // Check that stored data is encrypted (not plain text)
        $stored_data = get_option( 'wpmudev_drive_credentials' );
        $this->assertNotContains( $client_id, $stored_data );
        $this->assertNotContains( $client_secret, $stored_data );

        // Verify decryption works
        $decrypted = $this->drive_api->get_decrypted_credentials();
        $this->assertEquals( $client_id, $decrypted['client_id'] );
        $this->assertEquals( $client_secret, $decrypted['client_secret'] );
        $this->assertArrayHasKey( 'created_at', $decrypted );
        $this->assertArrayHasKey( 'created_by', $decrypted );
    }

    /**
     * Test Google Client ID validation
     */
    public function test_google_client_id_validation() {
        $reflection = new ReflectionClass( $this->drive_api );
        $method = $reflection->getMethod( 'validate_google_client_id' );
        $method->setAccessible( true );

        // Valid Client IDs
        $this->assertTrue( $method->invoke( $this->drive_api, '123456789-abcdefghijk.apps.googleusercontent.com' ) );
        $this->assertTrue( $method->invoke( $this->drive_api, '987654321-xyz123abc.apps.googleusercontent.com' ) );

        // Invalid Client IDs
        $this->assertFalse( $method->invoke( $this->drive_api, 'invalid_client_id' ) );
        $this->assertFalse( $method->invoke( $this->drive_api, 'test@example.com' ) );
        $this->assertFalse( $method->invoke( $this->drive_api, '123456789' ) );
        $this->assertFalse( $method->invoke( $this->drive_api, '' ) );
    }

    /**
     * Test auth endpoint returns auth URL when credentials exist
     */
    public function test_start_auth_with_credentials() {
        wp_set_current_user( $this->admin_user_id );

        // First save credentials
        $save_request = new WP_REST_Request( 'POST', '/wpmudev/v1/drive/save-credentials' );
        $save_request->set_param( 'client_id', '123456789-abcdefghijk.apps.googleusercontent.com' );
        $save_request->set_param( 'client_secret', 'valid_client_secret_123456789' );
        rest_get_server()->dispatch( $save_request );

        // Then test auth
        $auth_request = new WP_REST_Request( 'POST', '/wpmudev/v1/drive/auth' );
        $response = rest_get_server()->dispatch( $auth_request );
        $data = $response->get_data();

        $this->assertEquals( 200, $response->get_status() );
        $this->assertTrue( $data['success'] );
        $this->assertArrayHasKey( 'auth_url', $data );
        $this->assertStringContainsString( 'accounts.google.com', $data['auth_url'] );
    }

    /**
     * Test auth endpoint fails without credentials
     */
    public function test_start_auth_without_credentials() {
        wp_set_current_user( $this->admin_user_id );

        $request = new WP_REST_Request( 'POST', '/wpmudev/v1/drive/auth' );
        $response = rest_get_server()->dispatch( $request );
        $data = $response->get_data();

        $this->assertEquals( 400, $response->get_status() );
        $this->assertEquals( 'missing_credentials', $data['code'] );
    }

    /**
     * Test client secret validation
     */
    public function test_client_secret_validation() {
        wp_set_current_user( $this->admin_user_id );

        $request = new WP_REST_Request( 'POST', '/wpmudev/v1/drive/save-credentials' );
        $request->set_param( 'client_id', '123456789-abcdefghijk.apps.googleusercontent.com' );
        $request->set_param( 'client_secret', 'short' ); // Too short

        $response = rest_get_server()->dispatch( $request );

        $this->assertEquals( 400, $response->get_status() );
    }

    /**
     * Test logging functionality
     */
    public function test_credential_action_logging() {
        wp_set_current_user( $this->admin_user_id );

        $request = new WP_REST_Request( 'POST', '/wpmudev/v1/drive/save-credentials' );
        $request->set_param( 'client_id', '123456789-abcdefghijk.apps.googleusercontent.com' );
        $request->set_param( 'client_secret', 'valid_client_secret_123456789' );
        rest_get_server()->dispatch( $request );

        // Check that action was logged
        $log = get_transient( 'wpmudev_drive_credential_log' );
        $this->assertNotEmpty( $log );
        $this->assertEquals( 'save', $log[0]['action'] );
        $this->assertEquals( $this->admin_user_id, $log[0]['user_id'] );
        $this->assertArrayHasKey( 'timestamp', $log[0] );
        $this->assertArrayHasKey( 'ip', $log[0] );
    }

    /**
     * Test existing auth endpoint that was already there
     */
    public function test_get_auth_url_endpoint_exists() {
        $request = new WP_REST_Request( 'GET', '/wpmudev/v1/auth/auth-url' );
        $response = rest_get_server()->dispatch( $request );
        $error = $response->as_error();

        // Should not be "not found" error since route exists
        if ( is_wp_error( $error ) ) {
            $this->assertNotSame( 'rest_no_route', $error->get_error_code() );
        }
    }
}