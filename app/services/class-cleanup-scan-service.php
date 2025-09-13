<?php
/**
 * Cleanup Service
 *
 * @package WPMUDEV\PluginTest
 * @since 1.0.0
 */

namespace WPMUDEV\PluginTest\App\Service;

defined( 'WPINC' ) || die;

/**
 * Cleanup Service Class
 */
class Cleanup_Service {

    /**
     * Initialize cleanup hooks
     */
    public function init() {
        add_action( 'wpmudev_cleanup_scan_job', array( $this, 'cleanup_scan_job' ) );
    }

    /**
     * Clean up completed scan job data
     */
    public function cleanup_scan_job() {
        delete_option( 'wpmudev_background_scan_job' );
    }
}