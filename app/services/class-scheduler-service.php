<?php
/**
 * Scheduler Service
 *
 * @package WPMUDEV\PluginTest
 * @since 1.0.0
 */

namespace WPMUDEV\PluginTest\App\Service;

defined( 'WPINC' ) || die;

/**
 * Scheduler Service Class
 * 
 * Handles scheduled execution of post maintenance tasks
 * Following Single Responsibility Principle
 */
class Scheduler_Service {

    /**
     * Hook name for the scheduled event
     */
    const HOOK_NAME = 'wpmudev_daily_posts_maintenance';

    /**
     * Background Process Service
     *
     * @var Background_Process_Service
     */
    private $background_service;

    /**
     * Initialize the service
     */
    public function init() {
        // $this->background_service = new Background_Process_Service();
        
        // Register the scheduled event handler
        add_action( self::HOOK_NAME, array( $this, 'execute_daily_maintenance' ) );
        
        // Schedule the event if not already scheduled
        add_action( 'init', array( $this, 'schedule_daily_maintenance' ) );
        
        // Clean up on plugin deactivation
        register_deactivation_hook( WPMUDEV_PLUGINTEST_FILE, array( $this, 'unschedule_daily_maintenance' ) );
    }

    /**
     * Schedule daily maintenance if not already scheduled
     */
    public function schedule_daily_maintenance() {
        if ( ! wp_next_scheduled( self::HOOK_NAME ) ) {
            // Schedule for 2 AM daily
            $timestamp = strtotime( 'tomorrow 2:00 AM' );
            wp_schedule_event( $timestamp, 'daily', self::HOOK_NAME );
        }
    }

    /**
     * Unschedule daily maintenance
     */
    public function unschedule_daily_maintenance() {
        $timestamp = wp_next_scheduled( self::HOOK_NAME );
        if ( $timestamp ) {
            wp_unschedule_event( $timestamp, self::HOOK_NAME );
        }
    }

    /**
     * Execute the daily maintenance task
     */
    public function execute_daily_maintenance() {
        // FIXED: Create service instance only when needed
        if ( ! class_exists( 'WPMUDEV\PluginTest\App\Service\Background_Process_Service' ) ) {
            error_log( 'WPMUDEV: Background_Process_Service class not found for scheduled task' );
            return;
        }

        $background_service = new Background_Process_Service();
        
        // Don't run if another scan is already running
        if ( $background_service->is_processing() ) {
            return;
        }

        // Get default post types (can be filtered)
        $post_types = apply_filters( 'wpmudev_scheduled_scan_post_types', array( 'post', 'page' ) );
        $batch_size = apply_filters( 'wpmudev_scheduled_scan_batch_size', 50 );

        try {
            // Start background scan
            $job_id = $background_service->start_scan( $post_types, $batch_size );
            
            // Log the scheduled execution
            error_log( sprintf(
                'WPMUDEV Posts Maintenance: Daily scan started with job ID %s',
                $job_id
            ) );

        } catch ( Exception $e ) {
            // Log error
            error_log( sprintf(
                'WPMUDEV Posts Maintenance: Daily scan failed to start - %s',
                $e->getMessage()
            ) );
        }
    }

    /**
     * Get next scheduled maintenance time
     *
     * @return int|false Timestamp of next scheduled event, or false if not scheduled
     */
    public function get_next_scheduled_time() {
        return wp_next_scheduled( self::HOOK_NAME );
    }

    /**
     * Manually trigger maintenance (for testing)
     */
    public function trigger_maintenance_now() {
        $this->execute_daily_maintenance();
    }
}