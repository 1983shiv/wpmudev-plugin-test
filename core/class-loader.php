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
     * Posts Maintenance instance
     */
    public $posts_maintenance;

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

        // App files (existing Google Drive functionality)
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

        // ADDED: Posts Maintenance files
        $posts_maintenance_files = array(
            '/app/services/class-posts-scanner-service.php',
            '/app/services/class-background-process-service.php',
            '/app/services/class-scheduler-service.php',
            '/app/services/class-cleanup-scan-service.php',
            '/app/admin-pages/class-posts-maintenance.php',
        );

        // Combine all files
        $all_files = array_merge( $core_files, $app_files, $posts_maintenance_files );

        foreach ( $all_files as $file ) {
            $file_path = $plugin_dir . $file;
            if ( file_exists( $file_path ) ) {
                require_once $file_path;
                error_log( "✅ WPMUDEV: Loaded file: {$file_path}" );
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
            
            // IMPORTANT: Initialize Google Drive admin pages FIRST (parent menu)
            App\Admin_Pages\Google_Drive::instance()->init();
            
            // THEN: Initialize Posts Maintenance (submenu) - this will listen to the custom action
            $this->posts_maintenance = new \WPMUDEV\PluginTest\App\Admin_Pages\Posts_Maintenance();
            $this->init_posts_maintenance();

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

    /**
     * Initialize Posts Maintenance functionality
     * 
     * @since 1.0.0
     * @return void
     */

    private function init_posts_maintenance() {
        try {
            // Check if Posts Maintenance class exists
            if ( ! class_exists( '\WPMUDEV\PluginTest\App\Admin_Pages\Posts_Maintenance' ) ) {
                error_log( 'WPMUDEV: Posts_Maintenance class not found' );
                return;
            }
            $this->posts_maintenance = new App\Admin_Pages\Posts_Maintenance();
                $this->posts_maintenance->init();
            // IMPORTANT: Initialize Posts Maintenance AFTER Google Drive menu is set up
            // Use priority 11 to ensure it runs after the parent menu is registered
            // add_action( 'admin_menu', function() {
            //     $this->posts_maintenance = new App\Admin_Pages\Posts_Maintenance();
            //     $this->posts_maintenance->init();
            // }, 11 );

            // Initialize cleanup service
            if ( class_exists( '\WPMUDEV\PluginTest\App\Service\Cleanup_Service' ) ) {
                $cleanup_service = new App\Service\Cleanup_Service();
                $cleanup_service->init();
            }

            // Hook for plugin deactivation cleanup
            register_deactivation_hook( WPMUDEV_PLUGINTEST_FILE, array( $this, 'cleanup_on_deactivation' ) );

            // Fire action for extensions
            do_action( 'wpmudev_posts_maintenance_loaded' );

        } catch ( \Exception $e ) {
            error_log( 'WPMUDEV Posts Maintenance initialization error: ' . $e->getMessage() );
        }
    }
    // private function init_posts_maintenance() {
    //     try {
    //         // Check if Posts Maintenance class exists
    //         if ( ! class_exists( '\WPMUDEV\PluginTest\App\Admin_Pages\Posts_Maintenance' ) ) {
    //             error_log( 'WPMUDEV: Posts_Maintenance class not found' );
    //             return;
    //         }

    //         // Initialize Posts Maintenance admin page
    //         $this->posts_maintenance = new App\Admin_Pages\Posts_Maintenance();
    //         $this->posts_maintenance->init();

    //         // Initialize cleanup service
    //         if ( class_exists( '\WPMUDEV\PluginTest\App\Service\Cleanup_Service' ) ) {
    //             $cleanup_service = new App\Services\Cleanup_Service();
    //             $cleanup_service->init();
    //         }

    //         // Hook for plugin deactivation cleanup
    //         register_deactivation_hook( WPMUDEV_PLUGINTEST_FILE, array( $this, 'cleanup_on_deactivation' ) );

    //         // Fire action for extensions
    //         do_action( 'wpmudev_posts_maintenance_loaded' );

    //     } catch ( \Exception $e ) {
    //         error_log( 'WPMUDEV Posts Maintenance initialization error: ' . $e->getMessage() );
    //     }
    // }

    /**
     * Cleanup when plugin is deactivated
     * 
     * @since 1.0.0
     * @return void
     */
    public function cleanup_on_deactivation() {
        try {
            // Stop any running background processes
            if ( class_exists( '\WPMUDEV\PluginTest\App\Service\Background_Process_Service' ) ) {
                $background_service = new App\Service\Background_Process_Service();
                $background_service->stop_scan();
            }

            // Unschedule events
            if ( class_exists( '\WPMUDEV\PluginTest\App\Service\Scheduler_Service' ) ) {
                $scheduler_service = new App\Service\Scheduler_Service();
                $scheduler_service->unschedule_daily_maintenance();
            }

            // Clear WP Cron events
            wp_clear_scheduled_hook( 'wpmudev_process_scan_batch' );
            wp_clear_scheduled_hook( 'wpmudev_cleanup_scan_job' );
            wp_clear_scheduled_hook( 'wpmudev_daily_posts_maintenance' );

            // Clean up options (optional - you might want to keep data)
            // delete_option( 'wpmudev_background_scan_job' );
            // delete_option( 'wpmudev_last_scan_info' );

        } catch ( \Exception $e ) {
            error_log( 'WPMUDEV Cleanup error: ' . $e->getMessage() );
        }
    }

    /**
     * Get Posts Maintenance instance
     * 
     * @since 1.0.0
     * @return App\Admin_Pages\Posts_Maintenance|null
     */
    public function get_posts_maintenance() {
        return $this->posts_maintenance;
    }

    /**
     * Check if Posts Maintenance is available
     * 
     * @since 1.0.0
     * @return bool
     */
    public function is_posts_maintenance_available() {
        return ! is_null( $this->posts_maintenance );
    }
}