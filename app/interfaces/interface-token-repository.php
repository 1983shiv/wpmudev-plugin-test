<?php
/**
 * Token Repository Interface
 *
 * @package WPMUDEV\PluginTest\Interfaces
 */

namespace WPMUDEV\PluginTest\Interfaces;

interface Token_Repository_Interface {
    
    /**
     * Store access token
     *
     * @param array $token
     * @return bool
     */
    public function store_access_token( $token );
    
    /**
     * Get access token
     *
     * @return array|false
     */
    public function get_access_token();
    
    /**
     * Store refresh token
     *
     * @param string $token
     * @return bool
     */
    public function store_refresh_token( $token );
    
    /**
     * Get refresh token
     *
     * @return string|false
     */
    public function get_refresh_token();
    
    /**
     * Store token metadata
     *
     * @param array $metadata
     * @return bool
     */
    public function store_metadata( $metadata );
    
    /**
     * Get token metadata
     *
     * @return array
     */
    public function get_metadata();
    
    /**
     * Clear all tokens
     *
     * @return bool
     */
    public function clear_tokens();
    
    /**
     * Check if token is expired
     *
     * @return bool
     */
    public function is_token_expired();
    
    /**
     * Store token expiration time
     *
     * @param int $timestamp
     * @return bool
     */
    public function store_expiration( $timestamp );
}
