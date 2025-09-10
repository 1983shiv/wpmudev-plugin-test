<?php
/**
 * Google Drive API endpoints using Google Client Library.
 *
 * @link          https://wpmudev.com/
 * @since         1.0.0
 *
 * @author        WPMUDEV (https://wpmudev.com)
 * @package       WPMUDEV\PluginTest
 *
 * @copyright (c) 2025, Incsub (http://incsub.com)
 */

namespace WPMUDEV\PluginTest\Endpoints\V1;

// Abort if called directly.
defined( 'WPINC' ) || die;

use WPMUDEV\PluginTest\Base;
use WP_REST_Request;
use WP_REST_Response;
use WP_Error;
use Google_Client;
use Google_Service_Drive;
use Google_Service_Drive_DriveFile;
use Google_Service_Oauth2;

class Drive_API extends Base {

    /**
     * Google Client instance.
     *
     * @var Google_Client
     */
    private $client;

    /**
     * Google Drive service.
     *
     * @var Google_Service_Drive
     */
    private $drive_service;

    /**
     * OAuth redirect URI.
     *
     * @var string
     */
    private $redirect_uri;

    /**
     * Google Drive API scopes.
     *
     * @var array
     */
    private $scopes = array(
        Google_Service_Drive::DRIVE_FILE,
        Google_Service_Drive::DRIVE_READONLY,
    );

    /**
     * Initialize the class.
     */
    public function init() {
        $this->redirect_uri = home_url( '/wp-json/wpmudev/v1/drive/callback' );
        $this->setup_google_client();

        add_action( 'rest_api_init', array( $this, 'register_routes' ) );
    }

    /**
     * Setup Google Client.
     */
    private function setup_google_client() {
        $auth_creds = $this->get_decrypted_credentials();
        
        if ( empty( $auth_creds['client_id'] ) || empty( $auth_creds['client_secret'] ) ) {
            return;
        }

        $this->client = new Google_Client();
        $this->client->setClientId( $auth_creds['client_id'] );
        $this->client->setClientSecret( $auth_creds['client_secret'] );
        $this->client->setRedirectUri( $this->redirect_uri );
        $this->client->setScopes( $this->scopes );
        $this->client->setAccessType( 'offline' );
        $this->client->setPrompt( 'consent' );

        // Set access token if available and decrypt it
        $encrypted_token = get_option( 'wpmudev_drive_access_token', '' );
        if ( ! empty( $encrypted_token ) ) {
            $decrypted_token = $this->decrypt_token( $encrypted_token );
            if ( $decrypted_token ) {
                $this->client->setAccessToken( $decrypted_token );
            }
        }

        $this->drive_service = new Google_Service_Drive( $this->client );
    }

    /**
     * Register REST API routes.
     */
    public function register_routes() {
        // Save credentials endpoint
        register_rest_route( 'wpmudev/v1/drive', '/save-credentials', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'save_credentials' ),
            'permission_callback' => array( $this, 'check_permissions' ),
            'args'                => $this->get_save_credentials_args(),
        ) );

        // Get credentials endpoint
        register_rest_route( 'wpmudev/v1/drive', '/get-credentials', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'get_credentials' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        // Authentication endpoint
        register_rest_route( 'wpmudev/v1/drive', '/auth', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'start_auth' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        // Check authentication status
        register_rest_route( 'wpmudev/v1/drive', '/auth-status', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'get_auth_status' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        // Revoke authentication
        register_rest_route( 'wpmudev/v1/drive', '/revoke-auth', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'revoke_auth' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        // Refresh token manually
        register_rest_route( 'wpmudev/v1/drive', '/refresh-token', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'manual_refresh_token' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        // Debug endpoint (remove in production)
        register_rest_route( 'wpmudev/v1/drive', '/debug-state', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'debug_oauth_state' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        // OAuth callback
        register_rest_route( 'wpmudev/v1/drive', '/callback', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'handle_callback' ),
            'permission_callback' => '__return_true', // Public callback
        ) );

        // List files
        register_rest_route( 'wpmudev/v1/drive', '/files', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'list_files' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        // Upload file
        register_rest_route( 'wpmudev/v1/drive', '/upload', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'upload_file' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        // Download file
        register_rest_route( 'wpmudev/v1/drive', '/download', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'download_file' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        // Create folder
        register_rest_route( 'wpmudev/v1/drive', '/create-folder', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'create_folder' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );
    }

    /**
     * Save Google OAuth credentials.
     *
     * @param WP_REST_Request $request The REST request object.
     * @return WP_REST_Response|WP_Error Response object or error.
     */
    public function save_credentials( WP_REST_Request $request ) {
        try {
            // Get and validate parameters
            $client_id     = sanitize_text_field( $request->get_param( 'client_id' ) );
            $client_secret = sanitize_text_field( $request->get_param( 'client_secret' ) );

            // Validate required fields
            if ( empty( $client_id ) || empty( $client_secret ) ) {
                return new WP_Error(
                    'missing_credentials',
                    __( 'Client ID and Client Secret are required.', 'wpmudev-plugin-test' ),
                    array( 'status' => 400 )
                );
            }

            // Validate Client ID format
            if ( ! $this->validate_google_client_id( $client_id ) ) {
                return new WP_Error(
                    'invalid_client_id',
                    __( 'Invalid Client ID format.', 'wpmudev-plugin-test' ),
                    array( 'status' => 400 )
                );
            }

            // Encrypt credentials before storage
            $encrypted_credentials = $this->encrypt_credentials( array(
                'client_id'     => $client_id,
                'client_secret' => $client_secret,
                'created_at'    => current_time( 'mysql' ),
                'created_by'    => get_current_user_id(),
            ) );

            // Store encrypted credentials
            $saved = update_option( 'wpmudev_drive_credentials', $encrypted_credentials );

            if ( ! $saved ) {
                return new WP_Error(
                    'save_failed',
                    __( 'Failed to save credentials.', 'wpmudev-plugin-test' ),
                    array( 'status' => 500 )
                );
            }

            // Reinitialize Google Client with new credentials
            $this->setup_google_client();

            // Log the action for security audit
            $this->log_credential_action( 'save', get_current_user_id() );

            return new WP_REST_Response(
                array(
                    'success' => true,
                    'message' => __( 'Credentials saved successfully.', 'wpmudev-plugin-test' ),
                    'data'    => array(
                        'has_credentials' => true,
                        'client_id'       => substr( $client_id, 0, 10 ) . '...',
                    ),
                ),
                200
            );

        } catch ( Exception $e ) {
            return new WP_Error(
                'unexpected_error',
                __( 'An unexpected error occurred.', 'wpmudev-plugin-test' ),
                array( 'status' => 500 )
            );
        }
    }

    /**
     * Get stored credentials (masked for security)
     *
     * @param WP_REST_Request $request The REST request object.
     * @return WP_REST_Response|WP_Error Response object or error.
     */
    public function get_credentials( WP_REST_Request $request ) {
        $credentials = $this->get_decrypted_credentials();

        if ( empty( $credentials ) ) {
            return new WP_REST_Response(
                array(
                    'success'         => true,
                    'has_credentials' => false,
                    'data'            => null,
                ),
                200
            );
        }

        return new WP_REST_Response(
            array(
                'success'         => true,
                'has_credentials' => true,
                'data'            => array(
                    'client_id'  => isset( $credentials['client_id'] ) ? substr( $credentials['client_id'], 0, 10 ) . '...' : '',
                    'created_at' => isset( $credentials['created_at'] ) ? $credentials['created_at'] : '',
                ),
            ),
            200
        );
    }

    /**
     * Check if user has permission to manage credentials
     *
     * @return bool True if user has permission, false otherwise.
     */
    public function check_permissions() {
        return current_user_can( 'manage_options' );
    }

    /**
     * Get arguments for save credentials endpoint
     *
     * @return array Arguments array.
     */
    protected function get_save_credentials_args() {
        return array(
            'client_id' => array(
                'required'          => true,
                'type'              => 'string',
                'sanitize_callback' => 'sanitize_text_field',
                'validate_callback' => array( $this, 'validate_client_id_param' ),
                'description'       => __( 'Google OAuth Client ID', 'wpmudev-plugin-test' ),
            ),
            'client_secret' => array(
                'required'          => true,
                'type'              => 'string',
                'sanitize_callback' => 'sanitize_text_field',
                'validate_callback' => array( $this, 'validate_client_secret_param' ),
                'description'       => __( 'Google OAuth Client Secret', 'wpmudev-plugin-test' ),
            ),
        );
    }

    /**
     * Validate Client ID parameter
     *
     * @param string $param The parameter value.
     * @return bool True if valid, false otherwise.
     */
    public function validate_client_id_param( $param ) {
        return ! empty( $param ) && is_string( $param ) && $this->validate_google_client_id( $param );
    }

    /**
     * Validate Client Secret parameter
     *
     * @param string $param The parameter value.
     * @return bool True if valid, false otherwise.
     */
    public function validate_client_secret_param( $param ) {
        return ! empty( $param ) && is_string( $param ) && strlen( $param ) >= 20;
    }

    /**
     * Validate Google Client ID format
     *
     * @param string $client_id The client ID to validate.
     * @return bool True if valid format, false otherwise.
     */
    protected function validate_google_client_id( $client_id ) {
        // Google Client IDs typically end with .apps.googleusercontent.com
        return preg_match( '/^[0-9]+-[a-zA-Z0-9_]+\.apps\.googleusercontent\.com$/', $client_id );
    }

    /**
     * Encrypt credentials before storage
     *
     * @param array $credentials The credentials to encrypt.
     * @return string Encrypted credentials.
     */
    protected function encrypt_credentials( $credentials ) {
        $key = $this->get_encryption_key();
        $serialized = serialize( $credentials );
        
        // Use WordPress salt for additional security
        $salt = wp_salt( 'auth' );
        $data = $salt . $serialized;
        
        return base64_encode( openssl_encrypt( $data, 'AES-256-CBC', $key, 0, substr( md5( $key ), 0, 16 ) ) );
    }

    /**
     * Decrypt stored credentials
     *
     * @return array|false Decrypted credentials or false on failure.
     */
    public function get_decrypted_credentials() {
        $encrypted = get_option( 'wpmudev_drive_credentials' );
        
        if ( empty( $encrypted ) ) {
            return false;
        }

        try {
            $key = $this->get_encryption_key();
            $decrypted = openssl_decrypt( base64_decode( $encrypted ), 'AES-256-CBC', $key, 0, substr( md5( $key ), 0, 16 ) );
            
            if ( false === $decrypted ) {
                return false;
            }

            // Remove salt
            $salt = wp_salt( 'auth' );
            if ( 0 !== strpos( $decrypted, $salt ) ) {
                return false;
            }

            $serialized = substr( $decrypted, strlen( $salt ) );
            return unserialize( $serialized );

        } catch ( Exception $e ) {
            return false;
        }
    }

    /**
     * Get encryption key
     *
     * @return string Encryption key.
     */
    protected function get_encryption_key() {
        // Use WordPress constants for key generation
        $key_parts = array(
            defined( 'AUTH_KEY' ) ? AUTH_KEY : 'default_auth_key',
            defined( 'SECURE_AUTH_KEY' ) ? SECURE_AUTH_KEY : 'default_secure_key',
            get_site_url(),
        );
        
        return hash( 'sha256', implode( '|', $key_parts ) );
    }

    /**
     * Log credential actions for security audit
     *
     * @param string $action The action performed.
     * @param int    $user_id The user ID who performed the action.
     */
    protected function log_credential_action( $action, $user_id ) {
        $log_entry = array(
            'action'    => $action,
            'user_id'   => $user_id,
            'timestamp' => current_time( 'mysql' ),
            'ip'        => $this->get_client_ip(),
        );

        // Store in transient for recent activity (expires in 30 days)
        $existing_log = get_transient( 'wpmudev_drive_credential_log' ) ?: array();
        $existing_log[] = $log_entry;
        
        // Keep only last 50 entries
        if ( count( $existing_log ) > 50 ) {
            $existing_log = array_slice( $existing_log, -50 );
        }
        
        set_transient( 'wpmudev_drive_credential_log', $existing_log, 30 * DAY_IN_SECONDS );
    }

    /**
     * Get client IP address
     *
     * @return string Client IP address.
     */
    protected function get_client_ip() {
        $ip_keys = array( 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR' );
        
        foreach ( $ip_keys as $key ) {
            if ( array_key_exists( $key, $_SERVER ) && ! empty( $_SERVER[ $key ] ) ) {
                $ip = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
                if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
                    return $ip;
                }
            }
        }
        
        return '127.0.0.1';
    }

        /**
     * Validate OAuth state parameter for CSRF protection.
     *
     * @param string $received_state The state parameter received from Google.
     * @return bool True if state is valid, false otherwise.
     */
    protected function validate_oauth_state( $received_state ) {
        if ( empty( $received_state ) ) {
            return false;
        }

        // Check if the state exists in our transients
        $stored_time = get_transient( 'wpmudev_oauth_state_' . $received_state );
        
        if ( $stored_time === false ) {
            return false;
        }

        // Delete the used state to prevent replay attacks
        delete_transient( 'wpmudev_oauth_state_' . $received_state );
        
        return true;
    }

    /**
     * Store OAuth tokens securely.
     *
     * @param array $token_data Token data from Google.
     * @return bool True if tokens stored successfully, false otherwise.
     */
    protected function store_tokens( $token_data ) {
        try {
            // Encrypt and store access token
            $encrypted_token = $this->encrypt_token( $token_data );
            $access_stored = update_option( 'wpmudev_drive_access_token', $encrypted_token );

            // Store refresh token separately if available
            $refresh_stored = true;
            if ( isset( $token_data['refresh_token'] ) ) {
                $encrypted_refresh = $this->encrypt_token( $token_data['refresh_token'] );
                $refresh_stored = update_option( 'wpmudev_drive_refresh_token', $encrypted_refresh );
            }

            // Calculate and store expiration time
            $expires_in = isset( $token_data['expires_in'] ) ? (int) $token_data['expires_in'] : 3600;
            $expires_at = time() + $expires_in;
            $expires_stored = update_option( 'wpmudev_drive_token_expires', $expires_at );

            // Store token metadata
            $metadata = array(
                'created_at'    => current_time( 'mysql' ),
                'expires_at'    => date( 'Y-m-d H:i:s', $expires_at ),
                'scope'         => isset( $token_data['scope'] ) ? $token_data['scope'] : implode( ' ', $this->scopes ),
                'token_type'    => isset( $token_data['token_type'] ) ? $token_data['token_type'] : 'Bearer',
            );
            $metadata_stored = update_option( 'wpmudev_drive_token_metadata', $metadata );

            return $access_stored && $refresh_stored && $expires_stored && $metadata_stored;

        } catch ( Exception $e ) {
            error_log( 'WPMUDEV Drive: Token storage failed - ' . $e->getMessage() );
            return false;
        }
    }

    /**
     * Verify stored token by making a test API call.
     *
     * @return array Verification result with success status and user info.
     */
    protected function verify_token() {
        try {
            // Get user info to verify token works
            $oauth2_service = new Google_Service_Oauth2( $this->client );
            $user_info = $oauth2_service->userinfo->get();

            return array(
                'success'    => true,
                'user_id'    => $user_info->getId(),
                'user_email' => $user_info->getEmail(),
                'user_name'  => $user_info->getName(),
                'message'    => 'Token verified successfully',
            );

        } catch ( Exception $e ) {
            return array(
                'success' => false,
                'message' => 'Token verification failed: ' . $e->getMessage(),
            );
        }
    }

    /**
     * Handle OAuth errors with proper logging and user feedback.
     *
     * @param string $error_code The error code.
     * @param string $error_description The error description.
     */
    protected function handle_oauth_error( $error_code, $error_description ) {
        // Log the error
        error_log( "WPMUDEV Drive OAuth Error: {$error_code} - {$error_description}" );
        $this->log_auth_action( 'auth_error', 0, "{$error_code}: {$error_description}" );

        // Map common errors to user-friendly messages
        $error_messages = array(
            'access_denied'           => __( 'Access was denied. Please try again and grant the necessary permissions.', 'wpmudev-plugin-test' ),
            'invalid_request'         => __( 'Invalid request. Please try the authentication process again.', 'wpmudev-plugin-test' ),
            'unauthorized_client'     => __( 'Unauthorized client. Please check your Google OAuth credentials.', 'wpmudev-plugin-test' ),
            'unsupported_response_type' => __( 'Unsupported response type. Please contact support.', 'wpmudev-plugin-test' ),
            'invalid_scope'           => __( 'Invalid scope requested. Please contact support.', 'wpmudev-plugin-test' ),
            'server_error'            => __( 'Google server error. Please try again later.', 'wpmudev-plugin-test' ),
            'temporarily_unavailable' => __( 'Service temporarily unavailable. Please try again later.', 'wpmudev-plugin-test' ),
        );

        $user_message = isset( $error_messages[ $error_code ] ) 
            ? $error_messages[ $error_code ] 
            : sprintf( __( 'Authentication failed: %s', 'wpmudev-plugin-test' ), $error_description );

        // Redirect to error page
        $redirect_url = add_query_arg(
            array(
                'auth'  => 'error',
                'error' => urlencode( $error_code ),
                'msg'   => urlencode( $user_message ),
            ),
            admin_url( 'admin.php?page=wpmudev_plugintest_drive' )
        );

        wp_redirect( $redirect_url );
        exit;
    }

    /**
     * Encrypt token data.
     *
     * @param mixed $token Token data to encrypt.
     * @return string Encrypted token.
     */
    protected function encrypt_token( $token ) {
        $key = $this->get_encryption_key();
        $serialized = is_array( $token ) ? serialize( $token ) : $token;
        
        $salt = wp_salt( 'auth' );
        $data = $salt . $serialized;
        
        return base64_encode( openssl_encrypt( $data, 'AES-256-CBC', $key, 0, substr( md5( $key ), 0, 16 ) ) );
    }

    /**
     * Decrypt token data.
     *
     * @param string $encrypted_token Encrypted token.
     * @return mixed Decrypted token data or false on failure.
     */
    protected function decrypt_token( $encrypted_token ) {
        if ( empty( $encrypted_token ) ) {
            return false;
        }

        try {
            $key = $this->get_encryption_key();
            $decrypted = openssl_decrypt( base64_decode( $encrypted_token ), 'AES-256-CBC', $key, 0, substr( md5( $key ), 0, 16 ) );
            
            if ( false === $decrypted ) {
                return false;
            }

            $salt = wp_salt( 'auth' );
            if ( 0 !== strpos( $decrypted, $salt ) ) {
                return false;
            }

            $serialized = substr( $decrypted, strlen( $salt ) );
            
            // Try to unserialize, if it fails return as string
            $unserialized = @unserialize( $serialized );
            return $unserialized !== false ? $unserialized : $serialized;

        } catch ( Exception $e ) {
            return false;
        }
    }

    /**
     * Log authentication actions.
     *
     * @param string $action The action performed.
     * @param int    $user_id The user ID.
     * @param string $details Additional details.
     */
    protected function log_auth_action( $action, $user_id = 0, $details = '' ) {
        $log_entry = array(
            'action'    => $action,
            'user_id'   => $user_id,
            'details'   => $details,
            'timestamp' => current_time( 'mysql' ),
            'ip'        => $this->get_client_ip(),
            'user_agent' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
        );

        $existing_log = get_transient( 'wpmudev_drive_auth_log' ) ?: array();
        $existing_log[] = $log_entry;
        
        // Keep only last 100 entries
        if ( count( $existing_log ) > 100 ) {
            $existing_log = array_slice( $existing_log, -100 );
        }
        
        set_transient( 'wpmudev_drive_auth_log', $existing_log, 7 * DAY_IN_SECONDS );
    }



    /**
     * Start Google OAuth flow.
     *
     * @param WP_REST_Request $request The REST request object.
     * @return WP_REST_Response|WP_Error Response object or error.
     */
    public function start_auth( WP_REST_Request $request ) {
        try {
            // Check if credentials are configured
            if ( ! $this->client ) {
                return new WP_Error(
                    'missing_credentials',
                    __( 'Google OAuth credentials not configured. Please save your credentials first.', 'wpmudev-plugin-test' ),
                    array( 'status' => 400 )
                );
            }

            // Generate a unique state parameter (simpler approach)
            $state = wp_generate_password( 32, false, false );
            
            // Store state globally (not tied to specific user ID)
            set_transient( 'wpmudev_oauth_state_' . $state, time(), 600 ); // 10 minutes

            // Set state parameter
            $this->client->setState( $state );

            // Generate authorization URL
            $auth_url = $this->client->createAuthUrl();

            // Log authentication attempt
            $this->log_auth_action( 'auth_start', get_current_user_id() );

            return new WP_REST_Response(
                array(
                    'success'  => true,
                    'auth_url' => $auth_url,
                    'state'    => $state,
                    'message'  => __( 'Authorization URL generated successfully. Redirect user to this URL.', 'wpmudev-plugin-test' ),
                ),
                200
            );

        } catch ( Exception $e ) {
            $this->log_auth_action( 'auth_error', get_current_user_id(), $e->getMessage() );
            
            return new WP_Error(
                'auth_url_generation_failed',
                __( 'Failed to generate authorization URL: ', 'wpmudev-plugin-test' ) . $e->getMessage(),
                array( 'status' => 500 )
            );
        }
    }

     /**
     * Handle OAuth callback with enhanced security and error handling.
     *
     * @param WP_REST_Request $request The REST request object.
     * @return void Redirects user or shows error page.
     */
    public function handle_callback( WP_REST_Request $request ) {
        try {
            $code  = sanitize_text_field( $request->get_param( 'code' ) );
            $state = sanitize_text_field( $request->get_param( 'state' ) );
            $error = sanitize_text_field( $request->get_param( 'error' ) );

            // Debug logging
            error_log( "WPMUDEV Drive Callback Debug: code=" . (!empty($code) ? 'present' : 'missing') . ", state=" . $state . ", error=" . $error );

            // Handle OAuth errors from Google
            if ( ! empty( $error ) ) {
                $error_description = sanitize_text_field( $request->get_param( 'error_description' ) );
                $this->handle_oauth_error( $error, $error_description );
                return;
            }

            // Validate authorization code
            if ( empty( $code ) ) {
                $this->handle_oauth_error( 'missing_code', 'Authorization code not received from Google' );
                return;
            }

            // Validate state parameter (CSRF protection)
            if ( ! $this->validate_oauth_state( $state ) ) {
                error_log( "WPMUDEV Drive: State validation failed. Received: " . $state );
                $this->handle_oauth_error( 'invalid_state', 'Invalid state parameter - possible CSRF attack' );
                return;
            }

            // Initialize Google Client if not already done
            if ( ! $this->client ) {
                $this->setup_google_client();
                
                if ( ! $this->client ) {
                    $this->handle_oauth_error( 'client_setup_failed', 'Failed to initialize Google Client' );
                    return;
                }
            }

            // Exchange authorization code for access token
            $access_token = $this->client->fetchAccessTokenWithAuthCode( $code );

            // Check for token exchange errors
            if ( array_key_exists( 'error', $access_token ) ) {
                $error_msg = isset( $access_token['error_description'] ) 
                    ? $access_token['error_description'] 
                    : $access_token['error'];
                
                $this->handle_oauth_error( 'token_exchange_failed', $error_msg );
                return;
            }

            // Store tokens securely
            $token_stored = $this->store_tokens( $access_token );
            
            if ( ! $token_stored ) {
                $this->handle_oauth_error( 'token_storage_failed', 'Failed to store access tokens' );
                return;
            }

            // Verify token by making a test API call
            $verification_result = $this->verify_token();
            
            if ( ! $verification_result['success'] ) {
                $this->handle_oauth_error( 'token_verification_failed', $verification_result['message'] );
                return;
            }

            // Log successful authentication
            $this->log_auth_action( 'auth_success', 1, 'OAuth flow completed successfully' );

            // Redirect to success page
            $redirect_url = add_query_arg(
                array(
                    'auth'    => 'success',
                    'user'    => $verification_result['user_email'],
                    'expires' => get_option( 'wpmudev_drive_token_expires' ),
                ),
                admin_url( 'admin.php?page=wpmudev_plugintest_drive' )
            );

            wp_redirect( $redirect_url );
            exit;

        } catch ( Exception $e ) {
            error_log( "WPMUDEV Drive Callback Exception: " . $e->getMessage() );
            $this->handle_oauth_error( 'unexpected_error', $e->getMessage() );
        }
    }

    /**
     * Ensure we have a valid access token.
     */
    private function ensure_valid_token() {
        if ( ! $this->client ) {
            return false;
        }

        // Get current access token
        $encrypted_token = get_option( 'wpmudev_drive_access_token' );
        
        if ( empty( $encrypted_token ) ) {
            return false;
        }

        $access_token = $this->decrypt_token( $encrypted_token );
        
        if ( false === $access_token ) {
            return false;
        }

        // Set the access token
        $this->client->setAccessToken( $access_token );

        // Check if token is expired
        if ( $this->client->isAccessTokenExpired() ) {
            return $this->refresh_access_token();
        }

        return true;
    }

    /**
     * Refresh access token using refresh token.
     *
     * @return bool True if refresh successful, false otherwise.
     */
    private function refresh_access_token() {
        $encrypted_refresh_token = get_option( 'wpmudev_drive_refresh_token' );
        
        if ( empty( $encrypted_refresh_token ) ) {
            $this->log_auth_action( 'refresh_failed', 0, 'No refresh token available' );
            return false;
        }

        $refresh_token = $this->decrypt_token( $encrypted_refresh_token );
        
        if ( false === $refresh_token ) {
            $this->log_auth_action( 'refresh_failed', 0, 'Failed to decrypt refresh token' );
            return false;
        }

        try {
            // Attempt to refresh the token
            $new_token = $this->client->fetchAccessTokenWithRefreshToken( $refresh_token );
            
            if ( array_key_exists( 'error', $new_token ) ) {
                $error_msg = isset( $new_token['error_description'] ) 
                    ? $new_token['error_description'] 
                    : $new_token['error'];
                
                $this->log_auth_action( 'refresh_failed', 0, "Token refresh error: {$error_msg}" );
                
                // If refresh token is invalid, clear stored tokens
                if ( in_array( $new_token['error'], array( 'invalid_grant', 'invalid_request' ) ) ) {
                    $this->clear_stored_tokens();
                }
                
                return false;
            }

            // Store the new access token
            $token_stored = $this->store_tokens( $new_token );
            
            if ( ! $token_stored ) {
                $this->log_auth_action( 'refresh_failed', 0, 'Failed to store refreshed token' );
                return false;
            }

            $this->log_auth_action( 'refresh_success', 0, 'Token refreshed successfully' );
            return true;

        } catch ( Exception $e ) {
            $this->log_auth_action( 'refresh_error', 0, $e->getMessage() );
            return false;
        }
    }

    /**
     * Clear all stored tokens and related data.
     */
    public function clear_stored_tokens() {
        delete_option( 'wpmudev_drive_access_token' );
        delete_option( 'wpmudev_drive_refresh_token' );
        delete_option( 'wpmudev_drive_token_expires' );
        delete_option( 'wpmudev_drive_token_metadata' );
        
        $this->log_auth_action( 'tokens_cleared', get_current_user_id(), 'All tokens cleared' );
    }

    /**
     * Get authentication status.
     *
     * @param WP_REST_Request $request The REST request object.
     * @return WP_REST_Response Response object.
     */
    public function get_auth_status( WP_REST_Request $request ) {
        $access_token = get_option( 'wpmudev_drive_access_token' );
        $token_metadata = get_option( 'wpmudev_drive_token_metadata', array() );
        $expires_at = get_option( 'wpmudev_drive_token_expires', 0 );

        $is_authenticated = ! empty( $access_token );
        $is_expired = $expires_at > 0 && time() >= $expires_at;
        $has_refresh_token = ! empty( get_option( 'wpmudev_drive_refresh_token' ) );

        $response_data = array(
            'success'           => true,
            'is_authenticated'  => $is_authenticated,
            'is_expired'        => $is_expired,
            'has_refresh_token' => $has_refresh_token,
            'expires_at'        => $expires_at,
            'expires_in'        => $expires_at > 0 ? max( 0, $expires_at - time() ) : 0,
            'token_metadata'    => $token_metadata,
        );

        // If we have a token, try to validate it
        if ( $is_authenticated && $this->client ) {
            $token_valid = $this->ensure_valid_token();
            $response_data['token_valid'] = $token_valid;
            
            if ( $token_valid ) {
                $verification = $this->verify_token();
                $response_data['user_info'] = $verification['success'] ? array(
                    'email' => $verification['user_email'],
                    'name'  => $verification['user_name'],
                ) : null;
            }
        }

        return new WP_REST_Response( $response_data, 200 );
    }

    /**
     * Revoke authentication and clear tokens.
     *
     * @param WP_REST_Request $request The REST request object.
     * @return WP_REST_Response Response object.
     */
    public function revoke_auth( WP_REST_Request $request ) {
        try {
            // Try to revoke token with Google
            if ( $this->client && $this->ensure_valid_token() ) {
                try {
                    $this->client->revokeToken();
                } catch ( Exception $e ) {
                    // Log but don't fail - we'll clear local tokens anyway
                    error_log( 'WPMUDEV Drive: Token revocation failed - ' . $e->getMessage() );
                }
            }

            // Clear all stored tokens
            $this->clear_stored_tokens();

            return new WP_REST_Response(
                array(
                    'success' => true,
                    'message' => __( 'Authentication revoked successfully.', 'wpmudev-plugin-test' ),
                ),
                200
            );

        } catch ( Exception $e ) {
            return new WP_Error(
                'revoke_failed',
                __( 'Failed to revoke authentication: ', 'wpmudev-plugin-test' ) . $e->getMessage(),
                array( 'status' => 500 )
            );
        }
    }

    /**
     * Manually refresh access token.
     *
     * @param WP_REST_Request $request The REST request object.
     * @return WP_REST_Response|WP_Error Response object or error.
     */
    public function manual_refresh_token( WP_REST_Request $request ) {
        if ( ! $this->client ) {
            return new WP_Error(
                'no_client',
                __( 'Google client not initialized.', 'wpmudev-plugin-test' ),
                array( 'status' => 400 )
            );
        }

        $refresh_success = $this->refresh_access_token();

        if ( ! $refresh_success ) {
            return new WP_Error(
                'refresh_failed',
                __( 'Failed to refresh access token. Please re-authenticate.', 'wpmudev-plugin-test' ),
                array( 'status' => 401 )
            );
        }

        $expires_at = get_option( 'wpmudev_drive_token_expires', 0 );

        return new WP_REST_Response(
            array(
                'success'    => true,
                'message'    => __( 'Access token refreshed successfully.', 'wpmudev-plugin-test' ),
                'expires_at' => $expires_at,
                'expires_in' => $expires_at > 0 ? max( 0, $expires_at - time() ) : 0,
            ),
            200
        );
    }

    /**
     * Debug OAuth state (temporary - remove in production)
     */
    public function debug_oauth_state( WP_REST_Request $request ) {
        global $wpdb;
        
        $transient_prefix = '_transient_wpmudev_oauth_state_';
        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s",
                $transient_prefix . '%'
            )
        );

        

        return new WP_REST_Response( array(
            'stored_states' => $results,
            'current_user_id' => get_current_user_id(),
        ) );
    }

    /**
     * List files in Google Drive.
     */
    public function list_files( WP_REST_Request $request ) {
        if ( ! $this->ensure_valid_token() ) {
            return new WP_Error( 'no_access_token', 'Not authenticated with Google Drive', array( 'status' => 401 ) );
        }

        try {
            $page_size = intval( $request->get_param( 'pageSize' ) ) ?: 20;
            $query     = sanitize_text_field( $request->get_param( 'q' ) ) ?: 'trashed=false';

            $options = array(
                'pageSize' => $page_size,
                'q'        => $query,
                'fields'   => 'files(id,name,mimeType,size,modifiedTime,webViewLink)',
            );

            $results = $this->drive_service->files->listFiles( $options );
            $files   = $results->getFiles();

            $file_list = array();
            foreach ( $files as $file ) {
                $file_list[] = array(
                    'id'           => $file->getId(),
                    'name'         => $file->getName(),
                    'mimeType'     => $file->getMimeType(),
                    'size'         => $file->getSize(),
                    'modifiedTime' => $file->getModifiedTime(),
                    'webViewLink'  => $file->getWebViewLink(),
                );
            }

            return new WP_REST_Response( array(
                'success' => true,
                'files'   => $file_list,
            ) );

        } catch ( Exception $e ) {
            return new WP_Error( 'api_error', $e->getMessage(), array( 'status' => 500 ) );
        }
    }

    /**
     * Upload file to Google Drive.
     */
    public function upload_file( WP_REST_Request $request ) {
        if ( ! $this->ensure_valid_token() ) {
            return new WP_Error( 'no_access_token', 'Not authenticated with Google Drive', array( 'status' => 401 ) );
        }

        $files = $request->get_file_params();
        
        if ( empty( $files['file'] ) ) {
            return new WP_Error( 'no_file', 'No file provided', array( 'status' => 400 ) );
        }

        $file = $files['file'];
        
        if ( $file['error'] !== UPLOAD_ERR_OK ) {
            return new WP_Error( 'upload_error', 'File upload error', array( 'status' => 400 ) );
        }

        try {
            // Create file metadata
            $drive_file = new Google_Service_Drive_DriveFile();
            $drive_file->setName( $file['name'] );

            // Upload file
            $result = $this->drive_service->files->create(
                $drive_file,
                array(
                    'data'       => file_get_contents( $file['tmp_name'] ),
                    'mimeType'   => $file['type'],
                    'uploadType' => 'multipart',
                    'fields'     => 'id,name,mimeType,size,webViewLink',
                )
            );

            return new WP_REST_Response( array(
                'success' => true,
                'file'    => array(
                    'id'          => $result->getId(),
                    'name'        => $result->getName(),
                    'mimeType'    => $result->getMimeType(),
                    'size'        => $result->getSize(),
                    'webViewLink' => $result->getWebViewLink(),
                ),
            ) );

        } catch ( Exception $e ) {
            return new WP_Error( 'upload_failed', $e->getMessage(), array( 'status' => 500 ) );
        }
    }

    /**
     * Download file from Google Drive.
     */
    public function download_file( WP_REST_Request $request ) {
        if ( ! $this->ensure_valid_token() ) {
            return new WP_Error( 'no_access_token', 'Not authenticated with Google Drive', array( 'status' => 401 ) );
        }

        $file_id = sanitize_text_field( $request->get_param( 'file_id' ) );
        
        if ( empty( $file_id ) ) {
            return new WP_Error( 'missing_file_id', 'File ID is required', array( 'status' => 400 ) );
        }

        try {
            // Get file metadata
            $file = $this->drive_service->files->get( $file_id, array(
                'fields' => 'id,name,mimeType,size',
            ) );

            // Download file content
            $response = $this->drive_service->files->get( $file_id, array(
                'alt' => 'media',
            ) );

            $content = $response->getBody()->getContents();

            // Return file content as base64 for JSON response
            return new WP_REST_Response( array(
                'success'  => true,
                'content'  => base64_encode( $content ),
                'filename' => $file->getName(),
                'mimeType' => $file->getMimeType(),
            ) );

        } catch ( Exception $e ) {
            return new WP_Error( 'download_failed', $e->getMessage(), array( 'status' => 500 ) );
        }
    }

    /**
     * Create folder in Google Drive.
     */
    public function create_folder( WP_REST_Request $request ) {
        if ( ! $this->ensure_valid_token() ) {
            return new WP_Error( 'no_access_token', 'Not authenticated with Google Drive', array( 'status' => 401 ) );
        }

        $name = sanitize_text_field( $request->get_param( 'name' ) );
        
        if ( empty( $name ) ) {
            return new WP_Error( 'missing_name', 'Folder name is required', array( 'status' => 400 ) );
        }

        try {
            $folder = new Google_Service_Drive_DriveFile();
            $folder->setName( $name );
            $folder->setMimeType( 'application/vnd.google-apps.folder' );

            $result = $this->drive_service->files->create( $folder, array(
                'fields' => 'id,name,mimeType,webViewLink',
            ) );

            return new WP_REST_Response( array(
                'success' => true,
                'folder'  => array(
                    'id'          => $result->getId(),
                    'name'        => $result->getName(),
                    'mimeType'    => $result->getMimeType(),
                    'webViewLink' => $result->getWebViewLink(),
                ),
            ) );

        } catch ( Exception $e ) {
            return new WP_Error( 'create_failed', $e->getMessage(), array( 'status' => 500 ) );
        }
    }
}