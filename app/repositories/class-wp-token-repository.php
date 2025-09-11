<?php
/**
 * Token Repository Implementation
 *
 * @package WPMUDEV\PluginTest\Repositories
 */

namespace WPMUDEV\PluginTest\Repositories;

use WPMUDEV\PluginTest\Interfaces\Token_Repository_Interface;
use WPMUDEV\PluginTest\Interfaces\Encryption_Service_Interface;

// Abort if called directly.
defined( 'WPINC' ) || die;

class WP_Token_Repository implements Token_Repository_Interface {

    /**
     * Encryption service
     *
     * @var Encryption_Service_Interface
     */
    private $encryption_service;

    /**
     * Constructor
     *
     * @param Encryption_Service_Interface $encryption_service
     */
    public function __construct( Encryption_Service_Interface $encryption_service ) {
        $this->encryption_service = $encryption_service;
    }

    /**
     * Store access token
     *
     * @param array $token
     * @return bool
     */
    public function store_access_token( $token ) {
        $encrypted = $this->encryption_service->encrypt( $token );
        return update_option( 'wpmudev_drive_access_token', $encrypted );
    }

    /**
     * Get access token
     *
     * @return array|false
     */
    public function get_access_token() {
        $encrypted = get_option( 'wpmudev_drive_access_token' );
        if ( empty( $encrypted ) ) {
            return false;
        }
        return $this->encryption_service->decrypt( $encrypted );
    }

    /**
     * Store refresh token
     *
     * @param string $token
     * @return bool
     */
    public function store_refresh_token( $token ) {
        $encrypted = $this->encryption_service->encrypt( $token );
        return update_option( 'wpmudev_drive_refresh_token', $encrypted );
    }

    /**
     * Get refresh token
     *
     * @return string|false
     */
    public function get_refresh_token() {
        $encrypted = get_option( 'wpmudev_drive_refresh_token' );
        if ( empty( $encrypted ) ) {
            return false;
        }
        
        $decrypted = $this->encryption_service->decrypt( $encrypted );
        
        // Handle both string and array formats
        if ( is_array( $decrypted ) && isset( $decrypted['refresh_token'] ) ) {
            return $decrypted['refresh_token'];
        } elseif ( is_string( $decrypted ) ) {
            return $decrypted;
        }
        
        return false;
    }

    /**
     * Store token metadata
     *
     * @param array $metadata
     * @return bool
     */
    public function store_metadata( $metadata ) {
        return update_option( 'wpmudev_drive_token_metadata', $metadata );
    }

    /**
     * Get token metadata
     *
     * @return array
     */
    public function get_metadata() {
        return get_option( 'wpmudev_drive_token_metadata', array() );
    }

    /**
     * Clear all tokens
     *
     * @return bool
     */
    /**
     * Clear all tokens
     */
    public function clear_tokens() {
        delete_option( 'wpmudev_drive_access_token' );
        delete_option( 'wpmudev_drive_refresh_token' );
        delete_option( 'wpmudev_drive_token_expires' );
        delete_option( 'wpmudev_drive_token_metadata' );
        
        return true;
    }

    /**
     * Check if token is expired
     *
     * @return bool
     */
    public function is_token_expired() {
        $expires_at = get_option( 'wpmudev_drive_token_expires', 0 );
        return $expires_at > 0 && time() >= $expires_at;
    }

    /**
     * Store token expiration time
     *
     * @param int $timestamp
     * @return bool
     */
    public function store_expiration( $timestamp ) {
        return update_option( 'wpmudev_drive_token_expires', $timestamp );
    }
}
