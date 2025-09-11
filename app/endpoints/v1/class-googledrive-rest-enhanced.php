<?php
/**
 * Enhanced Drive API with OAuth 2.0 Authentication
 */

namespace WPMUDEV\PluginTest\Endpoints\V1;

use WPMUDEV\PluginTest\Base;
use WPMUDEV\PluginTest\Services\Interfaces\Auth_Service_Interface;
use WPMUDEV\PluginTest\Services\Interfaces\Token_Repository_Interface;
use WPMUDEV\PluginTest\Services\Interfaces\Logger_Service_Interface;
use WP_REST_Request;
use WP_REST_Response;
use WP_Error;
use Google_Client;
use Google_Service_Drive;
use Google_Service_Drive_DriveFile;
use Exception;

class Drive_API_Enhanced extends Base {

    /**
     * Google Client instance.
     */
    private $client;

    /**
     * Google Drive service.
     */
    private $drive_service;

    /**
     * OAuth redirect URI.
     */
    private $redirect_uri;

    /**
     * Google Drive API scopes.
     */
    private $scopes = array(
        'https://www.googleapis.com/auth/drive.file',
        'https://www.googleapis.com/auth/drive.readonly',
    );

    /**
     * Service dependencies
     */
    private $auth_service;
    private $token_repository;
    private $logger;

    /**
     * Initialize the class.
     */
    public function init() {
        // Get services from global container
        global $wpmudev_service_container;
        
        if ( ! $wpmudev_service_container ) {
            error_log( 'WPMUDEV: Service container not available' );
            return;
        }

        try {
            $this->auth_service = $wpmudev_service_container->make( 'auth_service' );
            $this->token_repository = $wpmudev_service_container->make( 'token_repository' );
            $this->logger = $wpmudev_service_container->make( 'logger_service' );
        } catch ( Exception $e ) {
            error_log( 'WPMUDEV: Failed to load services: ' . $e->getMessage() );
            return;
        }

        $this->redirect_uri = rest_url( 'wpmudev/v1/drive/callback' );
        $this->setup_google_client();
        
        add_action( 'rest_api_init', array( $this, 'register_routes' ) );
    }

    /**
     * Setup Google Client
     */
    private function setup_google_client() {
        $credentials = $this->get_credentials();
        
        if ( empty( $credentials['client_id'] ) || empty( $credentials['client_secret'] ) ) {
            return;
        }

        $this->client = new Google_Client();
        $this->client->setClientId( $credentials['client_id'] );
        $this->client->setClientSecret( $credentials['client_secret'] );
        $this->client->setRedirectUri( $this->redirect_uri );
        $this->client->setScopes( $this->scopes );
        $this->client->setAccessType( 'offline' );
        $this->client->setPrompt( 'consent' );

        // SSL configuration for localhost
        if ( wp_get_environment_type() === 'development' || strpos( home_url(), 'localhost' ) !== false ) {
            $guzzleClient = new \GuzzleHttp\Client([
                'verify' => false,
                'curl' => [
                    CURLOPT_SSL_VERIFYPEER => false,
                    CURLOPT_SSL_VERIFYHOST => false,
                ]
            ]);
            $this->client->setHttpClient( $guzzleClient );
        }

        // Load existing token
        $token = $this->token_repository->get_access_token();
        if ( $token ) {
            $this->client->setAccessToken( $token );
        }

        $this->drive_service = new Google_Service_Drive( $this->client );
    }

    /**
     * Get credentials (compatible with original format)
     */
    private function get_credentials() {
        // Try new encrypted format first
        global $wpmudev_service_container;
        if ( $wpmudev_service_container ) {
            try {
                $encryption_service = $wpmudev_service_container->make( 'encryption_service' );
                $encrypted_credentials = get_option( 'wpmudev_drive_credentials', '' );
                
                if ( ! empty( $encrypted_credentials ) ) {
                    $credentials = $encryption_service->decrypt( $encrypted_credentials );
                    if ( $credentials ) {
                        return $credentials;
                    }
                }
            } catch ( Exception $e ) {
                // Fall back to original format
            }
        }

        // Fall back to original format
        return get_option( 'wpmudev_plugin_tests_auth', array() );
    }

    /**
     * Register REST API routes
     */
    public function register_routes() {
        // Save credentials
        register_rest_route( 'wpmudev/v1/drive', '/save-credentials', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'save_credentials' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        // Enhanced auth endpoints
        register_rest_route( 'wpmudev/v1/drive', '/auth', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'start_auth' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        register_rest_route( 'wpmudev/v1/drive', '/callback', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'handle_callback' ),
            'permission_callback' => '__return_true',
        ) );

        register_rest_route( 'wpmudev/v1/drive', '/auth-status', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'get_auth_status' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        register_rest_route( 'wpmudev/v1/drive', '/refresh-token', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'refresh_token' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        register_rest_route( 'wpmudev/v1/drive', '/revoke-auth', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'revoke_auth' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        // File operations
        register_rest_route( 'wpmudev/v1/drive', '/files', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'list_files' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        register_rest_route( 'wpmudev/v1/drive', '/upload', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'upload_file' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        register_rest_route( 'wpmudev/v1/drive', '/download', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'download_file' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        register_rest_route( 'wpmudev/v1/drive', '/create-folder', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'create_folder' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );
    }

    /**
     * Check permissions
     */
    public function check_permissions() {
        return current_user_can( 'manage_options' );
    }

    // =====================================
    // ENHANCED AUTHENTICATION METHODS
    // =====================================

    /**
     * Save credentials (backward compatible)
     */
    public function save_credentials( WP_REST_Request $request ) {
        $client_id = sanitize_text_field( $request->get_param( 'client_id' ) );
        $client_secret = sanitize_text_field( $request->get_param( 'client_secret' ) );

        if ( empty( $client_id ) || empty( $client_secret ) ) {
            return new WP_Error( 'missing_credentials', 'Client ID and Secret are required', array( 'status' => 400 ) );
        }

        $credentials = array(
            'client_id'     => $client_id,
            'client_secret' => $client_secret,
        );

        // Save in both formats for compatibility
        update_option( 'wpmudev_plugin_tests_auth', $credentials );

        // Also save encrypted version if encryption service available
        global $wpmudev_service_container;
        if ( $wpmudev_service_container ) {
            try {
                $encryption_service = $wpmudev_service_container->make( 'encryption_service' );
                $encrypted = $encryption_service->encrypt( $credentials );
                update_option( 'wpmudev_drive_credentials', $encrypted );
            } catch ( Exception $e ) {
                // Continue with unencrypted version
            }
        }

        // Reinitialize client
        $this->setup_google_client();

        return new WP_REST_Response( array(
            'success' => true,
            'message' => 'Credentials saved successfully',
        ) );
    }

    /**
     * Start OAuth flow
     */
    public function start_auth( WP_REST_Request $request ) {
        try {
            if ( ! $this->client ) {
                return new WP_Error(
                    'missing_credentials',
                    'Google OAuth credentials not configured. Please save your credentials first.',
                    array( 'status' => 400 )
                );
            }

            $auth_data = $this->auth_service->generate_auth_url( $this->client );

            return new WP_REST_Response( array(
                'success'  => true,
                'auth_url' => $auth_data['auth_url'],
                'state'    => $auth_data['state'],
                'message'  => 'Authorization URL generated successfully. Redirect user to this URL.',
            ), 200 );

        } catch ( Exception $e ) {
            $this->logger->log_auth_action( 'auth_error', get_current_user_id(), $e->getMessage() );
            
            return new WP_Error(
                'auth_url_generation_failed',
                'Failed to generate authorization URL: ' . $e->getMessage(),
                array( 'status' => 500 )
            );
        }
    }

    /**
     * Handle OAuth callback
     */
    public function handle_callback( WP_REST_Request $request ) {
        try {
            $code  = sanitize_text_field( $request->get_param( 'code' ) );
            $state = sanitize_text_field( $request->get_param( 'state' ) );
            $error = sanitize_text_field( $request->get_param( 'error' ) );

            if ( ! empty( $error ) ) {
                $error_description = sanitize_text_field( $request->get_param( 'error_description' ) );
                throw new Exception( $error_description ?: $error );
            }

            if ( empty( $code ) ) {
                throw new Exception( 'Authorization code not received from Google' );
            }

            $success = $this->auth_service->handle_callback( $code, $state, $this->client );

            if ( ! $success ) {
                throw new Exception( 'Failed to process OAuth callback' );
            }

            $this->logger->log_auth_action( 'auth_success', 1, 'OAuth flow completed successfully' );

            // Redirect to success page
            $redirect_url = add_query_arg(
                array( 'auth' => 'success' ),
                admin_url( 'admin.php?page=wpmudev_plugintest_drive' )
            );

            wp_redirect( $redirect_url );
            exit;

        } catch ( Exception $e ) {
            $this->logger->log_auth_action( 'auth_error', 0, $e->getMessage() );
            
            $redirect_url = add_query_arg(
                array(
                    'auth' => 'error',
                    'msg'  => urlencode( 'Authentication failed: ' . $e->getMessage() ),
                ),
                admin_url( 'admin.php?page=wpmudev_plugintest_drive' )
            );

            wp_redirect( $redirect_url );
            exit;
        }
    }

    /**
     * Get authentication status
     */
    public function get_auth_status( WP_REST_Request $request ) {
        $is_authenticated = ! empty( $this->token_repository->get_access_token() );
        $is_expired = $this->token_repository->is_token_expired();
        $has_refresh_token = ! empty( $this->token_repository->get_refresh_token() );

        $response_data = array(
            'success'          => true,
            'is_authenticated' => $is_authenticated,
            'is_expired'       => $is_expired,
            'has_refresh_token' => $has_refresh_token,
            'token_valid'      => $is_authenticated && ! $is_expired,
        );

        // Add expiration info
        $expires_at = get_option( 'wpmudev_drive_token_expires', 0 );
        if ( $expires_at > 0 ) {
            $response_data['expires_at'] = $expires_at;
            $response_data['expires_in'] = max( 0, $expires_at - time() );
        }

        return new WP_REST_Response( $response_data, 200 );
    }

    /**
     * Refresh access token
     */
    public function refresh_token( WP_REST_Request $request ) {
        try {
            $success = $this->auth_service->refresh_token( $this->client );
            
            if ( ! $success ) {
                return new WP_Error(
                    'refresh_failed',
                    'Failed to refresh access token. Please re-authenticate.',
                    array( 'status' => 401 )
                );
            }

            return new WP_REST_Response( array(
                'success' => true,
                'message' => 'Token refreshed successfully.',
            ), 200 );

        } catch ( Exception $e ) {
            return new WP_Error( 'refresh_error', $e->getMessage(), array( 'status' => 500 ) );
        }
    }

    /**
     * Revoke authentication
     */
    public function revoke_auth( WP_REST_Request $request ) {
        try {
            $this->auth_service->revoke_token( $this->client );
            $this->token_repository->clear_tokens();

            return new WP_REST_Response( array(
                'success' => true,
                'message' => 'Authentication revoked successfully.',
            ), 200 );

        } catch ( Exception $e ) {
            return new WP_Error( 'revoke_failed', $e->getMessage(), array( 'status' => 500 ) );
        }
    }

    // =====================================
    // DRIVE API METHODS (Enhanced)
    // =====================================

    /**
     * Ensure valid token
     */
    private function ensure_valid_token() {
        if ( ! $this->client ) {
            return false;
        }

        $token = $this->token_repository->get_access_token();
        
        if ( ! $token ) {
            return false;
        }

        $this->client->setAccessToken( $token );

        if ( $this->client->isAccessTokenExpired() ) {
            return $this->auth_service->refresh_token( $this->client );
        }

        return true;
    }

    /**
     * List files (Enhanced)
     */
    public function list_files( WP_REST_Request $request ) {
        if ( ! $this->ensure_valid_token() ) {
            return new WP_Error( 'no_access_token', 'Not authenticated with Google Drive', array( 'status' => 401 ) );
        }

        try {
            $page_size = (int) $request->get_param( 'page_size' ) ?: 20;
            $query = $request->get_param( 'query' ) ?: 'trashed=false';

            $options = array(
                'pageSize' => min( $page_size, 100 ), // Limit max page size
                'q'        => sanitize_text_field( $query ),
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
                'count'   => count( $file_list ),
            ), 200 );

        } catch ( Exception $e ) {
            return new WP_Error( 'api_error', $e->getMessage(), array( 'status' => 500 ) );
        }
    }

    /**
     * Upload file (Enhanced - from original)
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
            $drive_file = new Google_Service_Drive_DriveFile();
            $drive_file->setName( $file['name'] );

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
            ), 200 );

        } catch ( Exception $e ) {
            return new WP_Error( 'upload_failed', $e->getMessage(), array( 'status' => 500 ) );
        }
    }

    /**
     * Download file (Enhanced - from original)
     */
    public function download_file( WP_REST_Request $request ) {
        if ( ! $this->ensure_valid_token() ) {
            return new WP_Error( 'no_access_token', 'Not authenticated with Google Drive', array( 'status' => 401 ) );
        }

        $file_id = $request->get_param( 'file_id' );
        
        if ( empty( $file_id ) ) {
            return new WP_Error( 'missing_file_id', 'File ID is required', array( 'status' => 400 ) );
        }

        try {
            $file = $this->drive_service->files->get( $file_id, array(
                'fields' => 'id,name,mimeType,size',
            ) );

            $response = $this->drive_service->files->get( $file_id, array(
                'alt' => 'media',
            ) );

            $content = $response->getBody()->getContents();

            return new WP_REST_Response( array(
                'success'  => true,
                'content'  => base64_encode( $content ),
                'filename' => $file->getName(),
                'mimeType' => $file->getMimeType(),
            ), 200 );

        } catch ( Exception $e ) {
            return new WP_Error( 'download_failed', $e->getMessage(), array( 'status' => 500 ) );
        }
    }

    /**
     * Create folder (Enhanced - from original)
     */
    public function create_folder( WP_REST_Request $request ) {
        if ( ! $this->ensure_valid_token() ) {
            return new WP_Error( 'no_access_token', 'Not authenticated with Google Drive', array( 'status' => 401 ) );
        }

        $name = $request->get_param( 'name' );
        
        if ( empty( $name ) ) {
            return new WP_Error( 'missing_name', 'Folder name is required', array( 'status' => 400 ) );
        }

        try {
            $folder = new Google_Service_Drive_DriveFile();
            $folder->setName( sanitize_text_field( $name ) );
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
            ), 200 );

        } catch ( Exception $e ) {
            return new WP_Error( 'create_failed', $e->getMessage(), array( 'status' => 500 ) );
        }
    }
}