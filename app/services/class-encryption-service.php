<?php
/**
 * Encryption Service Implementation
 *
 * @package WPMUDEV\PluginTest\Services
 */

namespace WPMUDEV\PluginTest\Services;

use WPMUDEV\PluginTest\Interfaces\Encryption_Service_Interface;
use Exception;

// Abort if called directly.
defined( 'WPINC' ) || die;

class Encryption_Service implements Encryption_Service_Interface {

    /**
     * Encrypt data
     *
     * @param mixed $data
     * @return string
     */
    public function encrypt( $data ) {
        $key = $this->get_key();
        $serialized = is_array( $data ) ? serialize( $data ) : $data;
        
        // Use a simple salt approach that works across all WordPress environments
        $salt = defined( 'NONCE_SALT' ) ? NONCE_SALT : 'default_salt_wpmudev';
        $data_with_salt = $salt . $serialized;
        
        return base64_encode( openssl_encrypt( $data_with_salt, 'AES-256-CBC', $key, 0, substr( md5( $key ), 0, 16 ) ) );
    }

    /**
     * Decrypt data
     *
     * @param string $encrypted_data
     * @return mixed|false
     */
    public function decrypt( $encrypted_data ) {
        if ( empty( $encrypted_data ) ) {
            return false;
        }

        try {
            $key = $this->get_key();
            $decrypted = openssl_decrypt( base64_decode( $encrypted_data ), 'AES-256-CBC', $key, 0, substr( md5( $key ), 0, 16 ) );
            
            if ( false === $decrypted ) {
                return false;
            }

            $salt = defined( 'NONCE_SALT' ) ? NONCE_SALT : 'default_salt_wpmudev';
            
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
     * Get encryption key
     *
     * @return string
     */
    public function get_key() {
        $key_parts = array(
            defined( 'AUTH_KEY' ) ? AUTH_KEY : 'default_auth_key_wpmudev',
            defined( 'SECURE_AUTH_KEY' ) ? SECURE_AUTH_KEY : 'default_secure_auth_key_wpmudev',
            defined( 'LOGGED_IN_KEY' ) ? LOGGED_IN_KEY : 'default_logged_in_key_wpmudev',
            defined( 'NONCE_KEY' ) ? NONCE_KEY : 'default_nonce_key_wpmudev',
        );
        
        // Add site URL if available
        if ( function_exists( 'get_site_url' ) ) {
            $key_parts[] = get_site_url();
        } else {
            $key_parts[] = 'default_site_url_wpmudev';
        }
        
        return hash( 'sha256', implode( '|', $key_parts ) );
    }
}
