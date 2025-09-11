<?php
/**
 * Logger Service Implementation
 *
 * @package WPMUDEV\PluginTest\Services
 */

namespace WPMUDEV\PluginTest\Services;

use WPMUDEV\PluginTest\Interfaces\Logger_Service_Interface;

// Abort if called directly.
defined( 'WPINC' ) || die;

class Logger_Service implements Logger_Service_Interface {

    /**
     * Log authentication action
     *
     * @param string $action
     * @param int $user_id
     * @param string $details
     * @return bool
     */
    public function log_auth_action( $action, $user_id = 0, $details = '' ) {
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
        
        return true;
    }

    /**
     * Get authentication log
     *
     * @return array
     */
    public function get_auth_log() {
        return get_transient( 'wpmudev_drive_auth_log' ) ?: array();
    }

    /**
     * Clear authentication log
     *
     * @return bool
     */
    public function clear_auth_log() {
        return delete_transient( 'wpmudev_drive_auth_log' );
    }

    /**
     * Get client IP address
     *
     * @return string
     */
    private function get_client_ip() {
        $ip_keys = array( 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR' );
        
        foreach ( $ip_keys as $key ) {
            if ( array_key_exists( $key, $_SERVER ) === true ) {
                foreach ( explode( ',', $_SERVER[ $key ] ) as $ip ) {
                    $ip = trim( $ip );
                    
                    if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) !== false ) {
                        return $ip;
                    }
                }
            }
        }
        
        return '127.0.0.1';
    }
}
