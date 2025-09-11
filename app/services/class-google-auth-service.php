<?php
/**
 * Google Authentication Service
 */

namespace WPMUDEV\PluginTest\Services;

use WPMUDEV\PluginTest\Interfaces\Auth_Service_Interface;
use WPMUDEV\PluginTest\Interfaces\Token_Repository_Interface;
use WPMUDEV\PluginTest\Interfaces\Logger_Service_Interface;
use Google_Client;
use Exception;

class Google_Auth_Service implements Auth_Service_Interface {

    /**
     * Token repository instance
     */
    private $token_repository;

    /**
     * Logger service instance
     */
    private $logger;

    /**
     * Constructor
     *
     * @param Token_Repository_Interface $token_repository Token repository
     * @param Logger_Service_Interface   $logger           Logger service
     */
    public function __construct( Token_Repository_Interface $token_repository, Logger_Service_Interface $logger ) {
        $this->token_repository = $token_repository;
        $this->logger = $logger;
    }

    /**
     * Generate authentication URL
     */
    public function generate_auth_url( Google_Client $client ) {
        $state = wp_generate_password( 32, false, false );
        
        $state_data = array(
            'created_at' => time(),
            'user_id' => get_current_user_id(),
            'ip' => $this->get_client_ip(),
        );
        
        set_transient( 'wpmudev_oauth_state_' . $state, $state_data, 1800 );
        
        $client->setState( $state );
        $auth_url = $client->createAuthUrl();
        
        $this->logger->log_auth_action( 'auth_start', get_current_user_id(), 'State: ' . $state );
        
        return array(
            'auth_url' => $auth_url,
            'state' => $state,
        );
    }

    /**
     * Handle OAuth callback
     */
    public function handle_callback( $code, $state, Google_Client $client ) {
        if ( ! $this->validate_oauth_state( $state ) ) {
            throw new Exception( 'Invalid state parameter - possible CSRF attack' );
        }
        
        $access_token = $client->fetchAccessTokenWithAuthCode( $code );
        
        if ( array_key_exists( 'error', $access_token ) ) {
            $error_msg = isset( $access_token['error_description'] ) 
                ? $access_token['error_description'] 
                : $access_token['error'];
            throw new Exception( $error_msg );
        }
        
        return $this->store_tokens( $access_token );
    }

    /**
     * Refresh access token
     */
    public function refresh_token( Google_Client $client ) {
        $refresh_token = $this->token_repository->get_refresh_token();
        
        if ( empty( $refresh_token ) ) {
            $this->logger->log_auth_action( 'refresh_failed', 0, 'No refresh token available' );
            return false;
        }

        try {
            // Ensure we have the refresh token set in the client
            $current_token = $this->token_repository->get_access_token();
            if ( $current_token && is_array( $current_token ) ) {
                $current_token['refresh_token'] = $refresh_token;
                $client->setAccessToken( $current_token );
            }

            $new_token = $client->fetchAccessTokenWithRefreshToken( $refresh_token );
            
            if ( array_key_exists( 'error', $new_token ) ) {
                $error_msg = isset( $new_token['error_description'] ) 
                    ? $new_token['error_description'] 
                    : $new_token['error'];
                
                $this->logger->log_auth_action( 'refresh_failed', 0, "Token refresh error: {$error_msg}" );
                
                // If refresh token is invalid, clear stored tokens
                if ( in_array( $new_token['error'], array( 'invalid_grant', 'invalid_request' ) ) ) {
                    $this->token_repository->clear_tokens();
                }
                
                return false;
            }

            // Ensure refresh token is preserved
            if ( ! isset( $new_token['refresh_token'] ) ) {
                $new_token['refresh_token'] = $refresh_token;
            }

            // Store the refreshed token
            $token_stored = $this->store_tokens( $new_token );
            
            if ( ! $token_stored ) {
                $this->logger->log_auth_action( 'refresh_failed', 0, 'Failed to store refreshed token' );
                return false;
            }

            // Update the client with the new token
            $client->setAccessToken( $new_token );

            $this->logger->log_auth_action( 'refresh_success', 0, 'Token refreshed successfully' );
            return true;

        } catch ( Exception $e ) {
            $this->logger->log_auth_action( 'refresh_error', 0, $e->getMessage() );
            return false;
        }
    }

    /**
     * Revoke token
     */
    public function revoke_token( Google_Client $client ) {
        $access_token = $this->token_repository->get_access_token();
        
        if ( $access_token ) {
            try {
                $client->setAccessToken( $access_token );
                $client->revokeToken();
                $this->logger->log_auth_action( 'token_revoked', get_current_user_id(), 'Token revoked successfully' );
            } catch ( Exception $e ) {
                $this->logger->log_auth_action( 'revoke_error', get_current_user_id(), $e->getMessage() );
                // Continue to clear local tokens even if revoke fails
            }
        }
        
        $this->token_repository->clear_tokens();
    }

    /**
     * Validate OAuth state parameter
     */
    private function validate_oauth_state( $received_state ) {
        if ( empty( $received_state ) ) {
            error_log( 'WPMUDEV Drive: Empty state received' );
            return false;
        }

        $state_data = get_transient( 'wpmudev_oauth_state_' . $received_state );
        
        if ( $state_data === false ) {
            error_log( 'WPMUDEV Drive: State not found in transients: ' . $received_state );
            return false;
        }

        // Validate state age (should be within 30 minutes)
        if ( isset( $state_data['created_at'] ) && ( time() - $state_data['created_at'] ) > 1800 ) {
            error_log( 'WPMUDEV Drive: State expired' );
            delete_transient( 'wpmudev_oauth_state_' . $received_state );
            return false;
        }

        // Delete the used state to prevent replay attacks
        delete_transient( 'wpmudev_oauth_state_' . $received_state );
        
        error_log( 'WPMUDEV Drive: State validated successfully' );
        return true;
    }

    /**
     * Store tokens using repository
     */
    private function store_tokens( $token_data ) {
        $success = true;
        
        // Store access token
        if ( isset( $token_data['access_token'] ) ) {
            $success = $success && $this->token_repository->store_access_token( $token_data );
        }
        
        // Store refresh token
        if ( isset( $token_data['refresh_token'] ) ) {
            $success = $success && $this->token_repository->store_refresh_token( $token_data['refresh_token'] );
        }
        
        // Store expiration
        if ( isset( $token_data['expires_in'] ) ) {
            $expires_at = time() + (int) $token_data['expires_in'];
            update_option( 'wpmudev_drive_token_expires', $expires_at );
        }
        
        // Store metadata
        $metadata = array(
            'created_at' => date( 'Y-m-d H:i:s' ),
            'expires_at' => isset( $expires_at ) ? date( 'Y-m-d H:i:s', $expires_at ) : null,
            'scope' => isset( $token_data['scope'] ) ? $token_data['scope'] : '',
            'token_type' => isset( $token_data['token_type'] ) ? $token_data['token_type'] : 'Bearer',
        );
        update_option( 'wpmudev_drive_token_metadata', $metadata );
        
        if ( $success ) {
            $this->logger->log_auth_action( 'tokens_stored', get_current_user_id(), 'Tokens stored successfully' );
        } else {
            $this->logger->log_auth_action( 'storage_failed', get_current_user_id(), 'Failed to store tokens' );
        }
        
        return $success;
    }

    /**
     * Get client IP address
     */
    private function get_client_ip() {
        $ip_keys = array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR' );
        
        foreach ( $ip_keys as $key ) {
            if ( ! empty( $_SERVER[ $key ] ) ) {
                $ip = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
                // Take the first IP if there are multiple
                $ip = explode( ',', $ip )[0];
                return trim( $ip );
            }
        }
        
        return '127.0.0.1';
    }
}