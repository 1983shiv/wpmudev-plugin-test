<?php
/**
 * Class to boot up plugin.
 *
 * @link    https://wpmudev.com/
 * @since   1.0.0
 *
 * @author  WPMUDEV (https://wpmudev.com)
 * @package WPMUDEV_PluginTest
 *
 * @copyright (c) 2025, Incsub (http://incsub.com)
 */

namespace WPMUDEV\PluginTest;

use WPMUDEV\PluginTest\Base;
use WPMUDEV\PluginTest\OAuth_Bootstrap;

// If this file is called directly, abort.
defined( 'WPINC' ) || die;

final class Loader extends Base {
    /**
     * OAuth Bootstrap instance
     */
    public $oauth_bootstrap;

    /**
     * Settings helper class instance.
     */
    public $settings;

    /**
     * Minimum supported php version.
     */
    public $php_version = '7.4';

    /**
     * Minimum WordPress version.
     */
    public $wp_version = '6.1';

    /**
     * Initialize functionality of the plugin.
     */
    protected function __construct() {
        if ( ! $this->can_boot() ) {
            return;
        }

        $this->load_required_files();
        $this->init();
    }

    /**
     * Load required files manually
     */
    private function load_required_files() {
        $plugin_dir = dirname( __DIR__ );
        
        // Core files
        $core_files = array(
            '/core/class-service-container.php',
            '/core/class-oauth-bootstrap.php',
        );

        // App files
        $app_files = array(
            '/app/interfaces/interface-encryption-service.php',
            '/app/interfaces/interface-logger-service.php',
            '/app/interfaces/interface-token-repository.php',
            '/app/interfaces/interface-auth-service.php',
            '/app/services/class-encryption-service.php',
            '/app/services/class-logger-service.php',
            '/app/services/class-google-auth-service.php',
			'/app/repositories/class-wp-token-repository.php',
            '/app/endpoints/v1/class-googledrive-rest-enhanced.php',
        );

        $all_files = array_merge( $core_files, $app_files );

        foreach ( $all_files as $file ) {
            $file_path = $plugin_dir . $file;
            if ( file_exists( $file_path ) ) {
                require_once $file_path;
            } else {
                error_log( "WPMUDEV: Required file not found: {$file_path}" );
            }
        }
    }

    /**
     * Main condition that checks if plugin parts should continue loading.
     */
    private function can_boot() {
        global $wp_version;

        return (
            version_compare( PHP_VERSION, $this->php_version, '>' ) &&
            version_compare( $wp_version, $this->wp_version, '>' )
        );
    }

    /**
     * Register all the actions and filters.
     */
    private function init() {
        try {
            // Initialize OAuth services FIRST
            $this->oauth_bootstrap = new OAuth_Bootstrap();
            $this->oauth_bootstrap->init();
            
            // Initialize admin pages
            App\Admin_Pages\Google_Drive::instance()->init();
            
            // Initialize ENHANCED Drive API 
            Endpoints\V1\Drive_API_Enhanced::instance()->init();

            // Note: Original Drive_API is NOT initialized anymore
            // Endpoints\V1\Drive_API::instance()->init(); // Replaced by Enhanced version
            
        } catch ( \Exception $e ) {
            error_log( 'WPMUDEV Plugin Test initialization error: ' . $e->getMessage() );
            
            // Fallback to original Drive API if enhanced fails
            if ( class_exists( '\WPMUDEV\PluginTest\Endpoints\V1\Drive_API' ) ) {
                Endpoints\V1\Drive_API::instance()->init();
            }
        }
    }
}
