<?php
/**
 * Posts Maintenance Admin Page
 *
 * @package WPMUDEV\PluginTest
 * @since 1.0.0
 */

namespace WPMUDEV\PluginTest\App\Admin_Pages;

defined( 'WPINC' ) || die;

use WPMUDEV\PluginTest\Base;
use WPMUDEV\PluginTest\App\Service\Posts_Scanner_Service;
use WPMUDEV\PluginTest\App\Service\Background_Process_Service;
use WPMUDEV\PluginTest\App\Service\Scheduler_Service;

use Exception;

/**
 * Posts Maintenance Admin Page Class
 * 
 * Handles the admin interface for posts maintenance functionality
 * Following Single Responsibility Principle - only handles admin page UI
 */
class Posts_Maintenance extends Base {

    /**
     * Page slug for the admin page
     *
     * @var string
     */
    private $page_slug = 'wpmudev_posts_maintenance';

    /**
     * Parent page slug (Google Drive Test)
     *
     * @var string
     */
    private $parent_slug = 'wpmudev_plugintest_drive';

    /**
     * Page hook suffix
     *
     * @var string
     */
    private $page_hook;

    /**
     * Posts Scanner Service
     *
     * @var Posts_Scanner_Service
     */
    private $scanner_service;

    /**
     * Background Process Service
     *
     * @var Background_Process_Service
     */
    private $background_service;

    /**
     * Scheduler Service
     *
     * @var Scheduler_Service
     */
    private $scheduler_service;

    /**
     * Initialize the admin page
     * 
     * Following Dependency Injection principle
     */
    public function init() {        
        // Try to initialize services with error handling
        try {
            $this->scanner_service = new Posts_Scanner_Service();
            
        } catch ( Exception $e ) {
            error_log( '❌ Scanner service error: ' . $e->getMessage() );
        }

        try {
            $this->background_service = new Background_Process_Service();
            
        } catch ( Exception $e ) {
            error_log( '❌ Background service error: ' . $e->getMessage() );
        }

        try {
            $this->scheduler_service = new Scheduler_Service();
            
        } catch ( Exception $e ) {
            error_log( '❌ Scheduler service error: ' . $e->getMessage() );
        }

        // WordPress hooks
        // add_action( 'wpmudev_drive_test_submenu_init', array( $this, 'register_admin_page' ) );
        add_action( 'admin_menu', array( $this, 'register_admin_page' ), 15 );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );

        // IMPORTANT: Debug AJAX hook registration
        error_log( '🔗 WPMUDEV: About to register AJAX hooks...' );
        
        add_action( 'wp_ajax_wpmudev_scan_posts', array( $this, 'handle_ajax_scan_posts' ) );
        error_log( '✅ WPMUDEV: Registered wp_ajax_wpmudev_scan_posts' );
        
        add_action( 'wp_ajax_wpmudev_get_scan_progress', array( $this, 'handle_ajax_get_progress' ) );
        error_log( '✅ WPMUDEV: Registered wp_ajax_wpmudev_get_scan_progress' );
        
        add_action( 'wp_ajax_wpmudev_stop_scan', array( $this, 'handle_ajax_stop_scan' ) );
        error_log( '✅ WPMUDEV: Registered wp_ajax_wpmudev_stop_scan' );

        // Initialize background processing and scheduling
        // $this->background_service->init();
        // $this->scheduler_service->init();
        // FIXED: Only initialize if services exist
        if ( $this->background_service ) {
            $this->background_service->init();
        }
        if ( $this->scheduler_service ) {
            $this->scheduler_service->init();
        }
    }

    /**
     * Register the admin page
     */
    // public function register_admin_page() {
    //     $this->page_hook = add_menu_page(
    //         __( 'Posts Maintenance', 'wpmudev-plugin-test' ),
    //         __( 'Posts Maintenance', 'wpmudev-plugin-test' ),
    //         'manage_options',
    //         $this->page_slug,
    //         array( $this, 'render_page' ),
    //         'dashicons-admin-tools',
    //         25
    //     );
    // }

    public function register_admin_page() {
        $this->page_hook = add_submenu_page(
            $this->parent_slug,                                  // Parent slug (Google Drive Test)
            __( 'Posts Maintenance', 'wpmudev-plugin-test' ),   // Page title
            __( 'Posts Maintenance', 'wpmudev-plugin-test' ),   // Menu title
            'manage_options',                                    // Capability
            $this->page_slug,                                    // Menu slug
            array( $this, 'render_page' )                       // Callback function
        );

        // ADDED: Debug logging
        if ( $this->page_hook ) {
            error_log( 'Posts Maintenance submenu registered successfully: ' . $this->page_hook );
        } else {
            error_log( 'Posts Maintenance submenu registration failed' );
        }
    }

    /**
     * Enqueue necessary assets for the admin page
     *
     * @param string $hook Current admin page hook
     */
    public function enqueue_assets( $hook ) {
        if ( $hook !== $this->page_hook ) {
            return;
        }

        wp_enqueue_script(
            'wpmudev-posts-maintenance',
            WPMUDEV_PLUGINTEST_URL . 'assets/js/posts-maintenance.js',
            array( 'jquery' ),
            WPMUDEV_PLUGINTEST_VERSION,
            true
        );

        wp_enqueue_style(
            'wpmudev-posts-maintenance',
            WPMUDEV_PLUGINTEST_URL . 'assets/css/posts-maintenance.css',
            array(),
            WPMUDEV_PLUGINTEST_VERSION
        );

        wp_localize_script(
            'wpmudev-posts-maintenance',
            'wpmudevPostsMaintenance',
            array(
                'nonce'     => wp_create_nonce( 'wpmudev_posts_maintenance' ),
                'ajaxUrl'   => admin_url( 'admin-ajax.php' ),
                'strings'   => array(
                    'scanStarted'       => __( 'Scan started successfully', 'wpmudev-plugin-test' ),
                    'scanCompleted'     => __( 'Scan completed successfully', 'wpmudev-plugin-test' ),
                    'scanStopped'       => __( 'Scan stopped', 'wpmudev-plugin-test' ),
                    'scanError'         => __( 'An error occurred during scanning', 'wpmudev-plugin-test' ),
                    'confirmStop'       => __( 'Are you sure you want to stop the scan?', 'wpmudev-plugin-test' ),
                    'processingPosts'   => __( 'Processing posts...', 'wpmudev-plugin-test' ),
                ),
            )
        );
    }

    /**
     * Render the admin page
     */
    // public function render_page() {
    //     $available_post_types = $this->get_available_post_types();
    //     $last_scan_info = $this->scanner_service->get_last_scan_info();
    //     $is_scan_running = $this->background_service->is_processing();
    //     $next_scheduled = $this->scheduler_service->get_next_scheduled_time();

    //     include WPMUDEV_PLUGINTEST_DIR . 'app/templates/posts-maintenance-page.php';
    // }

    public function render_page() {
        $available_post_types = $this->get_available_post_types();
        
        // ADDED: Safe fallbacks if services aren't available
        $last_scan_info = $this->scanner_service ? $this->scanner_service->get_last_scan_info() : array();
        $is_scan_running = $this->background_service ? $this->background_service->is_processing() : false;
        $next_scheduled = $this->scheduler_service ? $this->scheduler_service->get_next_scheduled_time() : false;

        // ADDED: Show error if services failed to initialize
        if ( ! $this->scanner_service || ! $this->background_service || ! $this->scheduler_service ) {
            echo '<div class="notice notice-error"><p>';
            echo __( 'Some services failed to initialize. Please check the error logs.', 'wpmudev-plugin-test' );
            echo '</p></div>';
        }

        include WPMUDEV_PLUGINTEST_DIR . 'app/templates/posts-maintenance-page.php';
    }

    /**
     * Handle AJAX request to start post scanning
     */
    // public function handle_ajax_scan_posts() {
    //     // Verify nonce and permissions
    //     if ( ! wp_verify_nonce( $_POST['nonce'], 'wpmudev_posts_maintenance' ) ) {
    //         wp_die( 'Security check failed' );
    //     }

    //     if ( ! current_user_can( 'manage_options' ) ) {
    //         wp_die( 'Insufficient permissions' );
    //     }

    //     $post_types = isset( $_POST['post_types'] ) ? array_map( 'sanitize_text_field', $_POST['post_types'] ) : array( 'post', 'page' );
    //     $batch_size = isset( $_POST['batch_size'] ) ? intval( $_POST['batch_size'] ) : 50;

    //     try {
    //         $job_id = $this->background_service->start_scan( $post_types, $batch_size );
            
    //         wp_send_json_success( array(
    //             'job_id' => $job_id,
    //             'message' => __( 'Scan started successfully', 'wpmudev-plugin-test' ),
    //         ) );
    //     } catch ( Exception $e ) {
    //         wp_send_json_error( array(
    //             'message' => $e->getMessage(),
    //         ) );
    //     }
    // }

    public function handle_ajax_scan_posts() {
        // FIXED: Check for nonce in both GET and POST
        $nonce = isset( $_POST['nonce'] ) ? $_POST['nonce'] : ( isset( $_GET['nonce'] ) ? $_GET['nonce'] : '' );
        
        if ( ! wp_verify_nonce( $nonce, 'wpmudev_posts_maintenance' ) ) {
            error_log( 'WPMUDEV: Nonce verification failed for scan_posts' );
            wp_send_json_error( array(
                'message' => 'Security check failed',
            ) );
            return;
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => 'Insufficient permissions',
            ) );
            return;
        }

        // ADDED: Check if service exists
        if ( ! $this->background_service ) {
            error_log( 'WPMUDEV: Background service not available for scan' );
            wp_send_json_error( array(
                'message' => 'Background service not available',
            ) );
            return;
        }

        $post_types = isset( $_POST['post_types'] ) ? array_map( 'sanitize_text_field', $_POST['post_types'] ) : array( 'post', 'page' );
        $batch_size = isset( $_POST['batch_size'] ) ? intval( $_POST['batch_size'] ) : 50;

        try {
            $job_id = $this->background_service->start_scan( $post_types, $batch_size );
            
            wp_send_json_success( array(
                'job_id' => $job_id,
                'message' => __( 'Scan started successfully', 'wpmudev-plugin-test' ),
            ) );
        } catch ( Exception $e ) {
            error_log( 'WPMUDEV: Error starting scan: ' . $e->getMessage() );
            wp_send_json_error( array(
                'message' => $e->getMessage(),
            ) );
        }
    }

    /**
     * Handle AJAX request to get scan progress
     */
    // public function handle_ajax_get_progress() {
    //     if ( ! wp_verify_nonce( $_GET['nonce'], 'wpmudev_posts_maintenance' ) ) {
    //         wp_die( 'Security check failed' );
    //     }

    //     $progress = $this->background_service->get_progress();
    //     wp_send_json_success( $progress );
    // }

    public function handle_ajax_get_progress() {
        // ADDED: Debug logging
        error_log( '🔍 WPMUDEV: handle_ajax_get_progress called' );
        error_log( '🔍 $_GET data: ' . print_r( $_GET, true ) );
        error_log( '🔍 $_POST data: ' . print_r( $_POST, true ) );

        // Check for both GET and POST nonce
        $nonce = isset( $_GET['nonce'] ) ? $_GET['nonce'] : ( isset( $_POST['nonce'] ) ? $_POST['nonce'] : '' );
        
        error_log( '🔍 Nonce received: ' . $nonce );
        
        if ( ! wp_verify_nonce( $nonce, 'wpmudev_posts_maintenance' ) ) {
            error_log( '❌ WPMUDEV: Nonce verification failed for get_progress' );
            error_log( '🔍 Expected nonce action: wpmudev_posts_maintenance' );
            wp_send_json_error( array(
                'message' => 'Security check failed',
            ) );
            return;
        }

        error_log( '✅ WPMUDEV: Nonce verified successfully' );

        // Check if service exists
        if ( ! $this->background_service ) {
            error_log( '❌ WPMUDEV: Background service not available' );
            wp_send_json_error( array(
                'message' => 'Service not available',
            ) );
            return;
        }

        try {
            $progress = $this->background_service->get_progress();
            error_log( '✅ WPMUDEV: Progress retrieved: ' . print_r( $progress, true ) );
            wp_send_json_success( $progress );
        } catch ( Exception $e ) {
            error_log( '❌ WPMUDEV: Error getting progress: ' . $e->getMessage() );
            wp_send_json_error( array(
                'message' => $e->getMessage(),
            ) );
        }
    }

    /**
     * Handle AJAX request to stop scan
     */
    // public function handle_ajax_stop_scan() {
    //     if ( ! wp_verify_nonce( $_POST['nonce'], 'wpmudev_posts_maintenance' ) ) {
    //         wp_die( 'Security check failed' );
    //     }

    //     if ( ! current_user_can( 'manage_options' ) ) {
    //         wp_die( 'Insufficient permissions' );
    //     }

    //     try {
    //         $this->background_service->stop_scan();
    //         wp_send_json_success( array(
    //             'message' => __( 'Scan stopped successfully', 'wpmudev-plugin-test' ),
    //         ) );
    //     } catch ( Exception $e ) {
    //         wp_send_json_error( array(
    //             'message' => $e->getMessage(),
    //         ) );
    //     }
    // }

    public function handle_ajax_stop_scan() {
        $nonce = isset( $_POST['nonce'] ) ? $_POST['nonce'] : ( isset( $_GET['nonce'] ) ? $_GET['nonce'] : '' );
        
        if ( ! wp_verify_nonce( $nonce, 'wpmudev_posts_maintenance' ) ) {
            wp_send_json_error( array(
                'message' => 'Security check failed',
            ) );
            return;
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => 'Insufficient permissions',
            ) );
            return;
        }

        // ADDED: Check if service exists
        if ( ! $this->background_service ) {
            wp_send_json_error( array(
                'message' => 'Background service not available',
            ) );
            return;
        }

        try {
            $this->background_service->stop_scan();
            wp_send_json_success( array(
                'message' => __( 'Scan stopped successfully', 'wpmudev-plugin-test' ),
            ) );
        } catch ( Exception $e ) {
            wp_send_json_error( array(
                'message' => $e->getMessage(),
            ) );
        }
    }

    /**
     * Get available post types for scanning
     *
     * @return array
     */
    private function get_available_post_types() {
        $post_types = get_post_types( array( 'public' => true ), 'objects' );
        $available = array();

        foreach ( $post_types as $post_type ) {
            $available[ $post_type->name ] = $post_type->label;
        }

        return $available;
    }
}