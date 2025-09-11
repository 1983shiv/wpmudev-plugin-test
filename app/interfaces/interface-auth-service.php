<?php
/**
 * Authentication Service Interface
 *
 * @package WPMUDEV\PluginTest\Interfaces
 */

namespace WPMUDEV\PluginTest\Interfaces;

use Google_Client;

interface Auth_Service_Interface {
    
    /**
     * Generate OAuth authorization URL
     *
     * @param Google_Client $client
     * @return array
     */
    public function generate_auth_url( Google_Client $client );
    
    /**
     * Handle OAuth callback
     *
     * @param string $code
     * @param string $state
     * @param Google_Client $client
     * @return bool
     */
    public function handle_callback( $code, $state, Google_Client $client );
    
    /**
     * Refresh access token
     *
     * @param Google_Client $client
     * @return bool
     */
    public function refresh_token( Google_Client $client );
    
    /**
     * Revoke authentication
     *
     * @param Google_Client $client
     * @return bool
     */
    public function revoke_token( Google_Client $client );
    
    /**
     * Validate OAuth state parameter
     *
     * @param string $state
     * @return bool
     */
    // public function validate_oauth_state( $state );
}
