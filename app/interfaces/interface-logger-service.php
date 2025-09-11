<?php
/**
 * Logger Service Interface
 *
 * @package WPMUDEV\PluginTest\Interfaces
 */

namespace WPMUDEV\PluginTest\Interfaces;

interface Logger_Service_Interface {
    
    /**
     * Log authentication action
     *
     * @param string $action
     * @param int $user_id
     * @param string $details
     * @return bool
     */
    public function log_auth_action( $action, $user_id = 0, $details = '' );
    
    /**
     * Get authentication log
     *
     * @return array
     */
    public function get_auth_log();
    
    /**
     * Clear authentication log
     *
     * @return bool
     */
    public function clear_auth_log();
}
