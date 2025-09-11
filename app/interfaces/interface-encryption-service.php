<?php
/**
 * Encryption Service Interface
 *
 * @package WPMUDEV\PluginTest\Interfaces
 */

namespace WPMUDEV\PluginTest\Interfaces;

interface Encryption_Service_Interface {
    
    /**
     * Encrypt data
     *
     * @param mixed $data
     * @return string
     */
    public function encrypt( $data );
    
    /**
     * Decrypt data
     *
     * @param string $encrypted_data
     * @return mixed|false
     */
    public function decrypt( $encrypted_data );
    
    /**
     * Get encryption key
     *
     * @return string
     */
    public function get_key();
}
