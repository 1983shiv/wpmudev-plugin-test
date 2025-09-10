<?php
/**
 * PHPUnit bootstrap file for WPMU DEV Plugin Test
 */

// Define test environment
if ( ! defined( 'WP_TESTS_DIR' ) ) {
    $wp_tests_dir = getenv( 'WP_TESTS_DIR' );
    
    if ( ! $wp_tests_dir ) {
        // Try common locations
        $possible_dirs = array(
            '/tmp/wordpress-tests-lib',
            'C:\Users\NINJAT~1\AppData\Local\Temp\wordpress-tests-lib',
            dirname( __FILE__ ) . '/../../../wordpress-tests-lib',
        );
        
        foreach ( $possible_dirs as $dir ) {
            if ( file_exists( $dir . '/includes/functions.php' ) ) {
                $wp_tests_dir = $dir;
                break;
            }
        }
    }
    
    if ( ! $wp_tests_dir ) {
        echo "WordPress test environment not found. Please run:\n";
        echo "bash bin/install-wp-tests.sh wordpress_test root '' localhost latest\n";
        exit( 1 );
    }
    
    define( 'WP_TESTS_DIR', $wp_tests_dir );
}

// Define test database
if ( ! defined( 'WP_TESTS_CONFIG_FILE_PATH' ) ) {
    define( 'WP_TESTS_CONFIG_FILE_PATH', WP_TESTS_DIR . '/wp-tests-config.php' );
}

// Load test environment
require_once WP_TESTS_DIR . '/includes/functions.php';

/**
 * Manually load the plugin being tested.
 */
function _manually_load_plugin() {
    require dirname( dirname( __FILE__ ) ) . '/wpmudev-plugin-test.php';
}
tests_add_filter( 'muplugins_loaded', '_manually_load_plugin' );

// Start up the WP testing environment
require WP_TESTS_DIR . '/includes/bootstrap.php';