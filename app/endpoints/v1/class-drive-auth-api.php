<?php
/**
 * Google Drive OAuth Authentication Endpoints
 *
 * @package WPMUDEV\PluginTest\Endpoints\V1
 */

namespace WPMUDEV\PluginTest\Endpoints\V1;

use WPMUDEV\PluginTest\Base;
use WPMUDEV\PluginTest\Interfaces\Auth_Service_Interface;
use WPMUDEV\PluginTest\Interfaces\Token_Repository_Interface;
use WPMUDEV\PluginTest\Interfaces\Logger_Service_Interface;
use WP_REST_Request;
use WP_REST_Response;
use WP_Error;
use Google_Client;
use Google_Service_Drive;
use Google_Service_Oauth2;
use Exception;

// Abort if called directly.
defined( 'WPINC' ) || die;

class Drive_Auth_API extends Base {

    /**
     * Authentication service
     *
     * @var Auth_Service_Interface
     */
    private $auth_service;

    /**
     * Token repository
     *
     * @var Token_Repository_Interface
     */
    private $token_repository;

    /**
     * Logger service
     *
     * @var Logger_Service_Interface
     */
    private $logger;

    /**
     * Google Client instance
     *
     * @var Google_Client
     */
    private $client;

    /**
     * OAuth redirect URI
     *
     * @var string
     */
    private $redirect_uri;

    /**
     * Google Drive API scopes
     *
     * @var array
     */
    private $scopes = array(
        'https://www.googleapis.com/auth/drive.file',
        'https://www.googleapis.com/auth/drive.readonly',
    );

    /**
     * Constructor
     *
     * @param Auth_Service_Interface $auth_service
     * @param Token_Repository_Interface $token_repository
     * @param Logger_Service_Interface $logger
     */
    public function __construct( 
        Auth_Service_Interface $auth_service,
        Token_Repository_Interface $token_repository,
        Logger_Service_Interface $logger
    ) {
        $this->auth_service = $auth_service;
        $this->token_repository = $token_repository;
        $this->logger = $logger;
    }

    /**
     * Initialize the auth API
     */
    public function init() {
        $this->redirect_uri = home_url( '/wp-json/wpmudev/v1/drive-auth/callback' );
        $this->setup_google_client();

        add_action( 'rest_api_init', array( $this, 'register_routes' ) );
    }

    /**
     * Setup Google Client
     */
    private function setup_google_client() {
        $auth_creds = get_option( 'wpmudev_plugin_tests_auth', array() );
        
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

        // Disable SSL verification for localhost development
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

        // Set access token if available
        $access_token = $this->token_repository->get_access_token();
        if ( $access_token ) {
            $this->client->setAccessToken( $access_token );
        }
    }

    /**
     * Register REST API routes
     */
    public function register_routes() {
        // Start authentication flow
        register_rest_route( 'wpmudev/v1/drive-auth', '/start', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'start_auth' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        // OAuth callback
        register_rest_route( 'wpmudev/v1/drive-auth', '/callback', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'handle_callback' ),
            'permission_callback' => '__return_true',
        ) );

        // Check authentication status
        register_rest_route( 'wpmudev/v1/drive-auth', '/status', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'get_auth_status' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        // Refresh token
        register_rest_route( 'wpmudev/v1/drive-auth', '/refresh', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'refresh_token' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        // Revoke authentication
        register_rest_route( 'wpmudev/v1/drive-auth', '/revoke', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'revoke_auth' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );
    }

    /**
     * Start Google OAuth flow
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function start_auth( WP_REST_Request $request ) {
        try {
            if ( ! $this->client ) {
                return new WP_Error(
                    'missing_credentials',
                    __( 'Google OAuth credentials not configured. Please save your credentials first.', 'wpmudev-plugin-test' ),
                    array( 'status' => 400 )
                );
            }

            $auth_data = $this->auth_service->generate_auth_url( $this->client );

            return new WP_REST_Response(
                array(
                    'success'  => true,
                    'auth_url' => $auth_data['auth_url'],
                    'state'    => $auth_data['state'],
                    'message'  => __( 'Authorization URL generated successfully. Redirect user to this URL.', 'wpmudev-plugin-test' ),
                ),
                200
            );

        } catch ( Exception $e ) {
            return new WP_Error(
                'auth_url_generation_failed',
                __( 'Failed to generate authorization URL: ', 'wpmudev-plugin-test' ) . $e->getMessage(),
                array( 'status' => 500 )
            );
        }
    }

    /**
     * Handle OAuth callback
     *
     * @param WP_REST_Request $request
     * @return void
     */
    public function handle_callback( WP_REST_Request $request ) {
        try {
            $code  = sanitize_text_field( $request->get_param( 'code' ) );
            $state = sanitize_text_field( $request->get_param( 'state' ) );
            $error = sanitize_text_field( $request->get_param( 'error' ) );

            if ( ! empty( $error ) ) {
                $error_description = sanitize_text_field( $request->get_param( 'error_description' ) );
                $this->handle_oauth_error( $error, $error_description ?: $error );
                return;
            }

            if ( empty( $code ) ) {
                $this->handle_oauth_error( 'missing_code', 'Authorization code not received from Google' );
                return;
            }

            if ( ! $this->client ) {
                $this->setup_google_client();
                
                if ( ! $this->client ) {
                    $this->handle_oauth_error( 'client_setup_failed', 'Failed to initialize Google Client' );
                    return;
                }
            }

            $success = $this->auth_service->handle_callback( $code, $state, $this->client );

            if ( ! $success ) {
                $this->handle_oauth_error( 'token_storage_failed', 'Failed to store access tokens' );
                return;
            }

            // Redirect to success page
            $redirect_url = add_query_arg(
                array(
                    'auth'    => 'success',
                    'message' => urlencode( 'Authentication successful' ),
                ),
                admin_url( 'admin.php?page=wpmudev_plugintest_drive' )
            );

            wp_redirect( $redirect_url );
            exit;

        } catch ( Exception $e ) {
            $this->handle_oauth_error( 'unexpected_error', $e->getMessage() );
        }
    }

    /**
     * Get authentication status
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public function get_auth_status( WP_REST_Request $request ) {
        $access_token = $this->token_repository->get_access_token();
        $token_metadata = $this->token_repository->get_metadata();
        $is_expired = $this->token_repository->is_token_expired();

        $is_authenticated = ! empty( $access_token );
        $has_refresh_token = ! empty( $this->token_repository->get_refresh_token() );

        $response_data = array(
            'success'           => true,
            'is_authenticated'  => $is_authenticated,
            'is_expired'        => $is_expired,
            'has_refresh_token' => $has_refresh_token,
            'token_metadata'    => $token_metadata,
            'token_valid'       => $is_authenticated && ! $is_expired,
        );

        return new WP_REST_Response( $response_data, 200 );
    }

    /**
     * Refresh access token
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function refresh_token( WP_REST_Request $request ) {
        if ( ! $this->client ) {
            return new WP_Error(
                'no_client',
                __( 'Google client not initialized.', 'wpmudev-plugin-test' ),
                array( 'status' => 400 )
            );
        }

        $success = $this->auth_service->refresh_token( $this->client );

        if ( ! $success ) {
            return new WP_Error(
                'refresh_failed',
                __( 'Failed to refresh access token. Please re-authenticate.', 'wpmudev-plugin-test' ),
                array( 'status' => 401 )
            );
        }

        return new WP_REST_Response(
            array(
                'success' => true,
                'message' => __( 'Access token refreshed successfully.', 'wpmudev-plugin-test' ),
            ),
            200
        );
    }

    /**
     * Revoke authentication
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function revoke_auth( WP_REST_Request $request ) {
        try {
            $success = $this->auth_service->revoke_token( $this->client );

            if ( ! $success ) {
                return new WP_Error(
                    'revoke_failed',
                    __( 'Failed to revoke authentication.', 'wpmudev-plugin-test' ),
                    array( 'status' => 500 )
                );
            }

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
     * Handle OAuth errors
     *
     * @param string $error_code
     * @param string $error_description
     */
    private function handle_oauth_error( $error_code, $error_description ) {
        $this->logger->log_auth_action( 'auth_error', 0, "{$error_code}: {$error_description}" );

        $redirect_url = add_query_arg(
            array(
                'auth'  => 'error',
                'error' => urlencode( $error_code ),
                'msg'   => urlencode( $error_description ),
            ),
            admin_url( 'admin.php?page=wpmudev_plugintest_drive' )
        );

        wp_redirect( $redirect_url );
        exit;
    }

    /**
     * Check permissions for authenticated endpoints
     *
     * @param WP_REST_Request $request
     * @return bool
     */
    public function check_permissions( WP_REST_Request $request ) {
        return current_user_can( 'manage_options' );
    }
}
