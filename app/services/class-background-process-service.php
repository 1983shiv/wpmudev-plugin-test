<?php

/**
 * Background Process Service
 *
 * @package WPMUDEV\PluginTest
 * @since 1.0.0
 */

namespace WPMUDEV\PluginTest\App\Service;

defined( 'WPINC' ) || die;

/**
 * Background Process Service Class
 */
class Background_Process_Service {

    /**
     * Option key for storing background job data
     */
    const OPTION_KEY = 'wpmudev_background_scan_job';

    /**
     * Posts Scanner Service
     *
     * @var Posts_Scanner_Service
     */
    public $scanner_service;

    /**
     * Initialize the service
     */
    public function init() {
        // $this->scanner_service = new Posts_Scanner_Service();
        
        // Hook for processing background jobs
        add_action( 'wp_ajax_nopriv_wpmudev_process_background_scan', array( $this, 'process_background_scan' ) );
        add_action( 'wp_ajax_wpmudev_process_background_scan', array( $this, 'process_background_scan' ) );
        
        // Hook for WordPress cron
        add_action( 'wpmudev_process_scan_batch', array( $this, 'process_scan_batch' ) );
    }

    /**
     * Start a background scan job
     *
     * @param array $post_types Post types to scan
     * @param int   $batch_size Batch size for processing
     * @return string Job ID
     */
    // public function start_scan( $post_types, $batch_size = 50 ) {
    //     // Generate unique job ID
    //     $job_id = uniqid( 'scan_', true );
        
    //     // Get total posts count
    //     $total_posts = $this->scanner_service->get_total_posts_count( $post_types );

    //     // Prepare job data
    //     $job_data = array(
    //         'job_id'        => $job_id,
    //         'post_types'    => $post_types,
    //         'batch_size'    => $batch_size,
    //         'total_posts'   => $total_posts,
    //         'processed'     => 0,
    //         'current_offset' => 0,
    //         'status'        => 'running',
    //         'start_time'    => current_time( 'timestamp' ),
    //         'errors'        => array(),
    //     );

    //     // Save job data
    //     update_option( self::OPTION_KEY, $job_data );

    //     // Schedule first batch
    //     wp_schedule_single_event( time(), 'wpmudev_process_scan_batch', array( $job_id ) );

    //     return $job_id;
    // }

    public function start_scan( $post_types, $batch_size = 50 ) {
        // FIXED: Create scanner service instance when needed
        if ( ! class_exists( 'WPMUDEV\PluginTest\App\Service\Posts_Scanner_Service' ) ) {
            throw new Exception( 'Posts_Scanner_Service class not found' );
        }

        $scanner_service = new Posts_Scanner_Service();
        
        // Generate unique job ID
        $job_id = uniqid( 'scan_', true );
        
        // Get total posts count
        $total_posts = $scanner_service->get_total_posts_count( $post_types );

        // Prepare job data
        $job_data = array(
            'job_id'        => $job_id,
            'post_types'    => $post_types,
            'batch_size'    => $batch_size,
            'total_posts'   => $total_posts,
            'processed'     => 0,
            'current_offset' => 0,
            'status'        => 'running',
            'start_time'    => current_time( 'timestamp' ),
            'errors'        => array(),
        );

        // Save job data
        update_option( self::OPTION_KEY, $job_data );

        // Schedule first batch
        wp_schedule_single_event( time(), 'wpmudev_process_scan_batch', array( $job_id ) );

        return $job_id;
    }

    /**
     * Process a batch of the scan job
     *
     * @param string $job_id Job ID
     */
    // public function process_scan_batch( $job_id ) {
    //     $job_data = get_option( self::OPTION_KEY, array() );

    //     // Verify job exists and is running
    //     if ( empty( $job_data ) || $job_data['job_id'] !== $job_id || $job_data['status'] !== 'running' ) {
    //         return;
    //     }

    //     try {
    //         // Process current batch
    //         $result = $this->scanner_service->scan_posts(
    //             $job_data['post_types'],
    //             $job_data['batch_size'],
    //             $job_data['current_offset']
    //         );

    //         // Update job data
    //         $job_data['processed'] += $result['processed'];
    //         $job_data['current_offset'] = $result['next_offset'];
    //         $job_data['errors'] = array_merge( $job_data['errors'], $result['errors'] );

    //         if ( $result['has_more'] && $job_data['status'] === 'running' ) {
    //             // Schedule next batch
    //             wp_schedule_single_event( time() + 2, 'wpmudev_process_scan_batch', array( $job_id ) );
    //             update_option( self::OPTION_KEY, $job_data );
    //         } else {
    //             // Job completed
    //             $this->complete_job( $job_data );
    //         }

    //     } catch ( \Exception $e ) {
    //         // Handle error
    //         $job_data['status'] = 'error';
    //         $job_data['errors'][] = $e->getMessage();
    //         update_option( self::OPTION_KEY, $job_data );
    //     }
    // }

    public function process_scan_batch( $job_id ) {
        $job_data = get_option( self::OPTION_KEY, array() );

        // Verify job exists and is running
        if ( empty( $job_data ) || $job_data['job_id'] !== $job_id || $job_data['status'] !== 'running' ) {
            return;
        }

        // FIXED: Create scanner service instance when needed
        if ( ! class_exists( 'WPMUDEV\PluginTest\App\Service\Posts_Scanner_Service' ) ) {
            error_log( 'WPMUDEV: Posts_Scanner_Service class not found for batch processing' );
            return;
        }

        $scanner_service = new Posts_Scanner_Service();

        try {
            // Process current batch
            $result = $scanner_service->scan_posts(
                $job_data['post_types'],
                $job_data['batch_size'],
                $job_data['current_offset']
            );

            // Update job data
            $job_data['processed'] += $result['processed'];
            $job_data['current_offset'] = $result['next_offset'];
            $job_data['errors'] = array_merge( $job_data['errors'], $result['errors'] );

            if ( $result['has_more'] && $job_data['status'] === 'running' ) {
                // Schedule next batch
                wp_schedule_single_event( time() + 2, 'wpmudev_process_scan_batch', array( $job_id ) );
                update_option( self::OPTION_KEY, $job_data );
            } else {
                // Job completed
                $this->complete_job( $job_data );
            }

        } catch ( Exception $e ) {
            // Handle error
            $job_data['status'] = 'error';
            $job_data['errors'][] = $e->getMessage();
            update_option( self::OPTION_KEY, $job_data );
        }
    }

    /**
     * Complete the scan job
     *
     * @param array $job_data Job data
     */
    private function complete_job( $job_data ) {
        $job_data['status'] = 'completed';
        $job_data['end_time'] = current_time( 'timestamp' );
        $job_data['duration'] = $job_data['end_time'] - $job_data['start_time'];

        // Save final job data
        update_option( self::OPTION_KEY, $job_data );

        // Save scan info for display
        $scan_info = array(
            'timestamp'     => $job_data['end_time'],
            'total_scanned' => $job_data['processed'],
            'post_types'    => $job_data['post_types'],
            'duration'      => $job_data['duration'],
        );
        update_option( 'wpmudev_last_scan_info', $scan_info );

        // Clean up job data after 24 hours
        wp_schedule_single_event( time() + DAY_IN_SECONDS, 'wpmudev_cleanup_scan_job' );

        // Fire completion action
        do_action( 'wpmudev_scan_completed', $job_data );
    }

    /**
     * Stop the current scan job
     */
    public function stop_scan() {
        $job_data = get_option( self::OPTION_KEY, array() );
        
        if ( ! empty( $job_data ) && $job_data['status'] === 'running' ) {
            $job_data['status'] = 'stopped';
            $job_data['end_time'] = current_time( 'timestamp' );
            update_option( self::OPTION_KEY, $job_data );
        }
    }

    /**
     * Get current scan progress
     *
     * @return array Progress information
     */
    public function get_progress() {
        $job_data = get_option( self::OPTION_KEY, array() );

        if ( empty( $job_data ) ) {
            return array(
                'status'     => 'idle',
                'progress'   => 0,
                'processed'  => 0,
                'total'      => 0,
                'errors'     => array(),
            );
        }

        $progress_percentage = $job_data['total_posts'] > 0 
            ? ( $job_data['processed'] / $job_data['total_posts'] ) * 100 
            : 0;

        return array(
            'status'     => $job_data['status'],
            'progress'   => round( $progress_percentage, 2 ),
            'processed'  => $job_data['processed'],
            'total'      => $job_data['total_posts'],
            'errors'     => $job_data['errors'],
            'job_id'     => $job_data['job_id'] ?? '',
        );
    }

    /**
     * Check if a scan is currently processing
     *
     * @return bool
     */
    public function is_processing() {
        $job_data = get_option( self::OPTION_KEY, array() );
        return ! empty( $job_data ) && $job_data['status'] === 'running';
    }

    /**
     * Process background scan via AJAX (fallback)
     */
    public function process_background_scan() {
        $job_data = get_option( self::OPTION_KEY, array() );
        
        if ( ! empty( $job_data ) && $job_data['status'] === 'running' ) {
            $this->process_scan_batch( $job_data['job_id'] );
        }
        
        wp_die();
    }
}