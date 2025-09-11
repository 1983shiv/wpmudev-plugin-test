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
     * List files with complete pagination support (Enhanced)
     */
    public function list_files( WP_REST_Request $request ) {
        if ( ! $this->ensure_valid_token() ) {
            return new WP_Error( 'no_access_token', 'Not authenticated with Google Drive', array( 'status' => 401 ) );
        }

        try {
            // Get pagination parameters
            $page_size = min( (int) $request->get_param( 'page_size' ) ?: 20, 100 ); // Max 100 items per page
            $page_token = sanitize_text_field( $request->get_param( 'page_token' ) );
            $query = sanitize_text_field( $request->get_param( 'query' ) ?: 'trashed=false' );
            $order_by = sanitize_text_field( $request->get_param( 'order_by' ) ?: 'modifiedTime desc' );
            
            // Validate order_by parameter
            $allowed_order_fields = array(
                'createdTime', 'folder', 'modifiedByMeTime', 'modifiedTime', 
                'name', 'quotaBytesUsed', 'recency', 'sharedWithMeTime', 'starred', 'viewedByMeTime'
            );
            
            $order_parts = explode( ' ', $order_by );
            $order_field = $order_parts[0] ?? 'modifiedTime';
            $order_direction = strtolower( $order_parts[1] ?? 'desc' );
            
            if ( ! in_array( $order_field, $allowed_order_fields ) ) {
                $order_field = 'modifiedTime';
            }
            
            if ( ! in_array( $order_direction, array( 'asc', 'desc' ) ) ) {
                $order_direction = 'desc';
            }
            
            $validated_order = $order_field . ' ' . $order_direction;

            // Build request options
            $options = array(
                'pageSize' => $page_size,
                'q'        => $query,
                'orderBy'  => $validated_order,
                'fields'   => 'files(id,name,mimeType,size,modifiedTime,webViewLink,parents,thumbnailLink,iconLink,createdTime,owners,shared),nextPageToken,incompleteSearch',
            );

            // Add page token for pagination
            if ( ! empty( $page_token ) ) {
                $options['pageToken'] = $page_token;
            }

            // Execute API request with retry logic
            $results = $this->execute_with_retry( function() use ( $options ) {
                return $this->drive_service->files->listFiles( $options );
            });

            if ( ! $results ) {
                throw new Exception( 'Failed to retrieve files from Google Drive after multiple attempts' );
            }

            $files = $results->getFiles();
            $next_page_token = $results->getNextPageToken();
            $incomplete_search = $results->getIncompleteSearch();

            // Process file list
            $file_list = array();
            foreach ( $files as $file ) {
                $file_data = array(
                    'id'           => $file->getId(),
                    'name'         => $file->getName(),
                    'mimeType'     => $file->getMimeType(),
                    'size'         => $file->getSize(),
                    'modifiedTime' => $file->getModifiedTime(),
                    'createdTime'  => $file->getCreatedTime(),
                    'webViewLink'  => $file->getWebViewLink(),
                    'parents'      => $file->getParents(),
                    'thumbnailLink' => $file->getThumbnailLink(),
                    'iconLink'     => $file->getIconLink(),
                    'isFolder'     => $file->getMimeType() === 'application/vnd.google-apps.folder',
                    'shared'       => $file->getShared(),
                );

                // Add formatted file size
                if ( $file->getSize() ) {
                    $file_data['sizeFormatted'] = $this->format_file_size( $file->getSize() );
                }

                // Add owner information
                $owners = $file->getOwners();
                if ( ! empty( $owners ) ) {
                    $file_data['owner'] = array(
                        'displayName' => $owners[0]->getDisplayName(),
                        'emailAddress' => $owners[0]->getEmailAddress(),
                    );
                }

                $file_list[] = $file_data;
            }

            // Build pagination info
            $pagination = array(
                'currentPageSize' => count( $file_list ),
                'requestedPageSize' => $page_size,
                'hasNextPage' => ! empty( $next_page_token ),
                'nextPageToken' => $next_page_token,
                'incompleteSearch' => $incomplete_search,
            );

            // Build response
            $response_data = array(
                'success'    => true,
                'files'      => $file_list,
                'pagination' => $pagination,
                'query'      => $query,
                'orderBy'    => $validated_order,
                'timestamp'  => current_time( 'c' ),
            );

            // Log successful request
            $this->logger->log_auth_action( 
                'files_listed', 
                get_current_user_id(), 
                sprintf( 'Listed %d files (page size: %d)', count( $file_list ), $page_size )
            );

            return new WP_REST_Response( $response_data, 200 );

        } catch ( Exception $e ) {
            // Log error
            $this->logger->log_auth_action( 'list_files_error', get_current_user_id(), $e->getMessage() );
            
            // Handle specific Google API errors
            if ( strpos( $e->getMessage(), 'quotaExceeded' ) !== false ) {
                return new WP_Error( 
                    'quota_exceeded', 
                    'Google Drive API quota exceeded. Please try again later.', 
                    array( 'status' => 429 )
                );
            }
            
            if ( strpos( $e->getMessage(), 'authError' ) !== false ) {
                return new WP_Error( 
                    'auth_error', 
                    'Authentication expired. Please re-authenticate.', 
                    array( 'status' => 401 )
                );
            }
            
            if ( strpos( $e->getMessage(), 'invalidQuery' ) !== false ) {
                return new WP_Error( 
                    'invalid_query', 
                    'Invalid search query. Please check your query syntax.', 
                    array( 'status' => 400 )
                );
            }

            return new WP_Error( 
                'api_error', 
                'Failed to retrieve files: ' . $e->getMessage(), 
                array( 'status' => 500 )
            );
        }
    }

    /**
     * Execute API request with retry logic
     */
    private function execute_with_retry( callable $request, $max_retries = 3 ) {
        $attempt = 0;
        
        while ( $attempt < $max_retries ) {
            try {
                return $request();
            } catch ( Exception $e ) {
                $attempt++;
                
                // Don't retry for auth errors or client errors
                if ( strpos( $e->getMessage(), 'authError' ) !== false || 
                    strpos( $e->getMessage(), 'invalid' ) !== false ) {
                    throw $e;
                }
                
                if ( $attempt >= $max_retries ) {
                    throw $e;
                }
                
                // Exponential backoff: wait 1s, 2s, 4s
                sleep( pow( 2, $attempt - 1 ) );
            }
        }
        
        return false;
    }

    /**
     * Format file size in human readable format
     */
    private function format_file_size( $bytes ) {
        if ( ! $bytes ) {
            return '0 B';
        }
        
        $units = array( 'B', 'KB', 'MB', 'GB', 'TB' );
        $bytes = max( $bytes, 0 );
        $pow = floor( ( $bytes ? log( $bytes ) : 0 ) / log( 1024 ) );
        $pow = min( $pow, count( $units ) - 1 );
        
        $bytes /= pow( 1024, $pow );
        
        return round( $bytes, 2 ) . ' ' . $units[ $pow ];
    }

    /**
     * Upload file (Enhanced - from original)
     */
    public function upload_file( WP_REST_Request $request ) {
        if ( ! $this->ensure_valid_token() ) {
            return new WP_Error( 'no_access_token', 'Not authenticated with Google Drive', array( 'status' => 401 ) );
        }

        $files = $request->get_file_params();
        $params = $request->get_params();
        
        if ( empty( $files['file'] ) ) {
            return new WP_Error( 'no_file', 'No file provided', array( 'status' => 400 ) );
        }

        $file = $files['file'];
        
        if ( $file['error'] !== UPLOAD_ERR_OK ) {
            return new WP_Error( 'upload_error', 'File upload error: ' . $this->get_upload_error_message( $file['error'] ), array( 'status' => 400 ) );
        }

        // Validate file size (max 100MB for this example)
        $max_size = 100 * 1024 * 1024; // 100MB
        if ( $file['size'] > $max_size ) {
            return new WP_Error( 'file_too_large', 'File size exceeds maximum allowed size (100MB)', array( 'status' => 400 ) );
        }

        try {
            $drive_file = new Google_Service_Drive_DriveFile();
            $drive_file->setName( sanitize_file_name( $file['name'] ) );

            // Set parent folder if provided
            $parent_folder = sanitize_text_field( $params['parent_folder'] ?? '' );
            if ( ! empty( $parent_folder ) ) {
                $drive_file->setParents( array( $parent_folder ) );
            }

            // Add description if provided
            $description = sanitize_textarea_field( $params['description'] ?? '' );
            if ( ! empty( $description ) ) {
                $drive_file->setDescription( $description );
            }

            $upload_params = array(
                'data'       => file_get_contents( $file['tmp_name'] ),
                'mimeType'   => $file['type'],
                'uploadType' => 'multipart',
                'fields'     => 'id,name,mimeType,size,webViewLink,parents,description,createdTime',
            );

            $result = $this->drive_service->files->create( $drive_file, $upload_params );

            $this->logger->log_auth_action( 'file_uploaded', get_current_user_id(), 'File uploaded: ' . $result->getName() );

            return new WP_REST_Response( array(
                'success' => true,
                'message' => 'File uploaded successfully',
                'file'    => array(
                    'id'          => $result->getId(),
                    'name'        => $result->getName(),
                    'mimeType'    => $result->getMimeType(),
                    'size'        => $result->getSize(),
                    'webViewLink' => $result->getWebViewLink(),
                    'parents'     => $result->getParents(),
                    'description' => $result->getDescription(),
                    'createdTime' => $result->getCreatedTime(),
                ),
            ), 200 );

        } catch ( Exception $e ) {
            $this->logger->log_auth_action( 'upload_failed', get_current_user_id(), $e->getMessage() );
            return new WP_Error( 'upload_failed', 'Upload failed: ' . $e->getMessage(), array( 'status' => 500 ) );
        }
    }

    /**
     * Download file (Enhanced - from original)
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
            // Get file metadata first
            $file = $this->drive_service->files->get( $file_id, array(
                'fields' => 'id,name,mimeType,size,parents',
            ) );

            // Check if it's a Google Workspace document (needs export)
            $google_docs_types = array(
                'application/vnd.google-apps.document',
                'application/vnd.google-apps.spreadsheet',
                'application/vnd.google-apps.presentation',
                'application/vnd.google-apps.drawing',
            );

            if ( in_array( $file->getMimeType(), $google_docs_types ) ) {
                return $this->export_google_doc( $file_id, $file );
            }

            // Download regular file
            $response = $this->drive_service->files->get( $file_id, array(
                'alt' => 'media',
            ) );

            $content = $response->getBody()->getContents();

            $this->logger->log_auth_action( 'file_downloaded', get_current_user_id(), 'File downloaded: ' . $file->getName() );

            // Return file content as base64 for JSON response
            return new WP_REST_Response( array(
                'success'   => true,
                'message'   => 'File downloaded successfully',
                'file'      => array(
                    'id'       => $file->getId(),
                    'name'     => $file->getName(),
                    'mimeType' => $file->getMimeType(),
                    'size'     => $file->getSize(),
                    'content'  => base64_encode( $content ),
                ),
            ), 200 );

        } catch ( Exception $e ) {
            $this->logger->log_auth_action( 'download_failed', get_current_user_id(), $e->getMessage() );
            return new WP_Error( 'download_failed', 'Download failed: ' . $e->getMessage(), array( 'status' => 500 ) );
        }
    }

    /**
     * Export Google Workspace documents
     */
    private function export_google_doc( $file_id, $file ) {
        $export_formats = array(
            'application/vnd.google-apps.document'     => 'application/pdf',
            'application/vnd.google-apps.spreadsheet' => 'application/pdf',
            'application/vnd.google-apps.presentation' => 'application/pdf',
            'application/vnd.google-apps.drawing'     => 'application/pdf',
        );

        $mime_type = $file->getMimeType();
        $export_type = $export_formats[ $mime_type ] ?? 'application/pdf';

        $response = $this->drive_service->files->export( $file_id, $export_type, array(
            'alt' => 'media',
        ) );

        $content = $response->getBody()->getContents();

        return new WP_REST_Response( array(
            'success'   => true,
            'message'   => 'Google document exported successfully',
            'file'      => array(
                'id'          => $file->getId(),
                'name'        => $file->getName() . '.pdf',
                'mimeType'    => $export_type,
                'originalType' => $mime_type,
                'content'     => base64_encode( $content ),
            ),
        ), 200 );
    }

    /**
     * Get upload error message
     */
    private function get_upload_error_message( $error_code ) {
        $errors = array(
            UPLOAD_ERR_INI_SIZE   => 'File exceeds upload_max_filesize directive',
            UPLOAD_ERR_FORM_SIZE  => 'File exceeds MAX_FILE_SIZE directive',
            UPLOAD_ERR_PARTIAL    => 'File was only partially uploaded',
            UPLOAD_ERR_NO_FILE    => 'No file was uploaded',
            UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',
            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',
            UPLOAD_ERR_EXTENSION  => 'Upload stopped by extension',
        );

        return $errors[ $error_code ] ?? 'Unknown upload error';
    }

    /**
     * Create folder (Enhanced - from original)
     */
    public function create_folder( WP_REST_Request $request ) {
        if ( ! $this->ensure_valid_token() ) {
            return new WP_Error( 'no_access_token', 'Not authenticated with Google Drive', array( 'status' => 401 ) );
        }

        $name = sanitize_text_field( $request->get_param( 'name' ) );
        $parent_folder = sanitize_text_field( $request->get_param( 'parent_folder' ) );
        $description = sanitize_textarea_field( $request->get_param( 'description' ) );
        
        if ( empty( $name ) ) {
            return new WP_Error( 'missing_name', 'Folder name is required', array( 'status' => 400 ) );
        }

        // Validate folder name
        if ( strlen( $name ) > 255 ) {
            return new WP_Error( 'name_too_long', 'Folder name cannot exceed 255 characters', array( 'status' => 400 ) );
        }

        try {
            $folder = new Google_Service_Drive_DriveFile();
            $folder->setName( $name );
            $folder->setMimeType( 'application/vnd.google-apps.folder' );

            // Set parent folder if provided
            if ( ! empty( $parent_folder ) ) {
                $folder->setParents( array( $parent_folder ) );
            }

            // Set description if provided
            if ( ! empty( $description ) ) {
                $folder->setDescription( $description );
            }

            $result = $this->drive_service->files->create( $folder, array(
                'fields' => 'id,name,mimeType,webViewLink,parents,description,createdTime',
            ) );

            $this->logger->log_auth_action( 'folder_created', get_current_user_id(), 'Folder created: ' . $result->getName() );

            return new WP_REST_Response( array(
                'success' => true,
                'message' => 'Folder created successfully',
                'folder'  => array(
                    'id'          => $result->getId(),
                    'name'        => $result->getName(),
                    'mimeType'    => $result->getMimeType(),
                    'webViewLink' => $result->getWebViewLink(),
                    'parents'     => $result->getParents(),
                    'description' => $result->getDescription(),
                    'createdTime' => $result->getCreatedTime(),
                ),
            ), 200 );

        } catch ( Exception $e ) {
            $this->logger->log_auth_action( 'folder_creation_failed', get_current_user_id(), $e->getMessage() );
            return new WP_Error( 'create_failed', 'Folder creation failed: ' . $e->getMessage(), array( 'status' => 500 ) );
        }
    }
}