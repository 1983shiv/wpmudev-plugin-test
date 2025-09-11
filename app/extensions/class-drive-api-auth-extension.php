<?php
/**
 * Drive API Authentication Extension
 * 
 * This class extends the existing Drive_API with OAuth functionality
 * without modifying the original class
 *
 * @package WPMUDEV\PluginTest\Extensions
 */

namespace WPMUDEV\PluginTest\Extensions;

use WPMUDEV\PluginTest\Base;
use WPMUDEV\PluginTest\Endpoints\V1\Drive_API;
use WPMUDEV\PluginTest\OAuth_Bootstrap;
use WP_REST_Request;
use WP_REST_Response;
use WP_Error;

// Abort if called directly.
defined( 'WPINC' ) || die;

class Drive_API_Auth_Extension extends Base {

    /**
     * OAuth Bootstrap instance
     *
     * @var OAuth_Bootstrap
     */
    private $oauth_bootstrap;

    /**
     * Initialize the extension
     */
    public function init() {
        $this->oauth_bootstrap = new OAuth_Bootstrap();
        
        // Hook into REST API initialization to add auth endpoints
        add_action( 'rest_api_init', array( $this, 'register_auth_routes' ), 20 );
    }

    /**
     * Register authentication routes that extend the existing Drive API
     */
    public function register_auth_routes() {
        // Enhanced auth endpoints with better paths
        register_rest_route( 'wpmudev/v1/drive', '/auth-enhanced', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'start_enhanced_auth' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        register_rest_route( 'wpmudev/v1/drive', '/auth-status-enhanced', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'get_enhanced_auth_status' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        register_rest_route( 'wpmudev/v1/drive', '/refresh-token-enhanced', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'refresh_token_enhanced' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        register_rest_route( 'wpmudev/v1/drive', '/revoke-auth-enhanced', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'revoke_auth_enhanced' ),
            'permission_callback' => array( $this, 'check_permissions' ),
        ) );

        // Enhanced callback that works with existing redirect URI
        register_rest_route( 'wpmudev/v1/drive', '/callback-enhanced', array(
            'methods'             => 'GET',
            'callback'            => array( $this, 'handle_enhanced_callback' ),
            'permission_callback' => '__return_true',
        ) );
    }

    /**
     * Enhanced authentication start
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function start_enhanced_auth( WP_REST_Request $request ) {
        try {
            $container = $this->oauth_bootstrap->get_container();
            $auth_api = $container->make( 'drive_auth_api' );
            
            return $auth_api->start_auth( $request );
            
        } catch ( Exception $e ) {
            return new WP_Error(
                'enhanced_auth_failed',
                'Enhanced authentication failed: ' . $e->getMessage(),
                array( 'status' => 500 )
            );
        }
    }

    /**
     * Enhanced authentication status
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public function get_enhanced_auth_status( WP_REST_Request $request ) {
        try {
            $container = $this->oauth_bootstrap->get_container();
            $auth_api = $container->make( 'drive_auth_api' );
            
            return $auth_api->get_auth_status( $request );
            
        } catch ( Exception $e ) {
            return new WP_REST_Response(
                array(
                    'success' => false,
                    'error' => $e->getMessage(),
                ),
                500
            );
        }
    }

    /**
     * Enhanced token refresh
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function refresh_token_enhanced( WP_REST_Request $request ) {
        try {
            $container = $this->oauth_bootstrap->get_container();
            $auth_api = $container->make( 'drive_auth_api' );
            
            return $auth_api->refresh_token( $request );
            
        } catch ( Exception $e ) {
            return new WP_Error(
                'enhanced_refresh_failed',
                'Enhanced token refresh failed: ' . $e->getMessage(),
                array( 'status' => 500 )
            );
        }
    }

    /**
     * Enhanced authentication revocation
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function revoke_auth_enhanced( WP_REST_Request $request ) {
        try {
            $container = $this->oauth_bootstrap->get_container();
            $auth_api = $container->make( 'drive_auth_api' );
            
            return $auth_api->revoke_auth( $request );
            
        } catch ( Exception $e ) {
            return new WP_Error(
                'enhanced_revoke_failed',
                'Enhanced authentication revocation failed: ' . $e->getMessage(),
                array( 'status' => 500 )
            );
        }
    }

    /**
     * Enhanced callback handler
     *
     * @param WP_REST_Request $request
     * @return void
     */
    public function handle_enhanced_callback( WP_REST_Request $request ) {
        try {
            $container = $this->oauth_bootstrap->get_container();
            $auth_api = $container->make( 'drive_auth_api' );
            
            $auth_api->handle_callback( $request );
            
        } catch ( Exception $e ) {
            // Redirect to error page if callback fails
            $redirect_url = add_query_arg(
                array(
                    'auth'  => 'error',
                    'error' => urlencode( 'enhanced_callback_failed' ),
                    'msg'   => urlencode( $e->getMessage() ),
                ),
                admin_url( 'admin.php?page=wpmudev_plugintest_drive' )
            );

            wp_redirect( $redirect_url );
            exit;
        }
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

    /**
     * Get authentication service for external use
     *
     * @return object|null
     */
    public function get_auth_service() {
        try {
            $container = $this->oauth_bootstrap->get_container();
            return $container->make( 'auth_service' );
        } catch ( Exception $e ) {
            return null;
        }
    }

    /**
     * Get token repository for external use
     *
     * @return object|null
     */
    public function get_token_repository() {
        try {
            $container = $this->oauth_bootstrap->get_container();
            return $container->make( 'token_repository' );
        } catch ( Exception $e ) {
            return null;
        }
    }
}
