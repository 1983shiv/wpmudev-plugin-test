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

        // Set access token if available
        $access_token = get_option( 'wpmudev_drive_access_token', '' );
        if ( ! empty( $access_token ) ) {
            $this->client->setAccessToken( $access_token );
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
     * Start Google OAuth flow.
     */
    public function start_auth() {
        if ( ! $this->client ) {
            return new WP_Error( 'missing_credentials', 'Google OAuth credentials not configured', array( 'status' => 400 ) );
        }

        $auth_url = $this->client->createAuthUrl();

        return new WP_REST_Response( array(
            'success' => true,
            'auth_url' => $auth_url,
        ) );
    }

    /**
     * Handle OAuth callback.
     */
    public function handle_callback( WP_REST_Request $request ) {
        $code  = sanitize_text_field( $request->get_param( 'code' ) );
        $state = sanitize_text_field( $request->get_param( 'state' ) );

        if ( empty( $code ) ) {
            wp_die( 'Authorization code not received' );
        }

        try {
            // Exchange code for access token
            $access_token = $this->client->fetchAccessTokenWithAuthCode( $code );

            if ( array_key_exists( 'error', $access_token ) ) {
                wp_die( 'Error getting access token: ' . esc_html( $access_token['error'] ) );
            }

            // Store tokens
            update_option( 'wpmudev_drive_access_token', $access_token );
            if ( isset( $access_token['refresh_token'] ) ) {
                update_option( 'wpmudev_drive_refresh_token', $access_token['refresh_token'] );
            }
            
            $expires_in = isset( $access_token['expires_in'] ) ? time() + $access_token['expires_in'] : time() + 3600;
            update_option( 'wpmudev_drive_token_expires', $expires_in );

            // Redirect back to admin page
            wp_redirect( admin_url( 'admin.php?page=wpmudev_plugintest_drive&auth=success' ) );
            exit;

        } catch ( Exception $e ) {
            wp_die( 'Failed to get access token: ' . esc_html( $e->getMessage() ) );
        }
    }

    /**
     * Ensure we have a valid access token.
     */
    private function ensure_valid_token() {
        if ( ! $this->client ) {
            return false;
        }

        // Check if token is expired and refresh if needed
        if ( $this->client->isAccessTokenExpired() ) {
            $refresh_token = get_option( 'wpmudev_drive_refresh_token' );
            
            if ( empty( $refresh_token ) ) {
                return false;
            }

            try {
                $new_token = $this->client->fetchAccessTokenWithRefreshToken( $refresh_token );
                
                if ( array_key_exists( 'error', $new_token ) ) {
                    return false;
                }

                update_option( 'wpmudev_drive_access_token', $new_token );
                $expires_in = isset( $new_token['expires_in'] ) ? time() + $new_token['expires_in'] : time() + 3600;
                update_option( 'wpmudev_drive_token_expires', $expires_in );
                
                return true;
            } catch ( Exception $e ) {
                return false;
            }
        }

        return true;
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