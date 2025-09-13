<?php
/**
 * Posts Scanner Service
 *
 * @package WPMUDEV\PluginTest
 * @since 1.0.0
 */

namespace WPMUDEV\PluginTest\App\Service;


defined( 'WPINC' ) || die;

/**
 * Posts Scanner Service Class
 * 
 * Handles the core logic for scanning and updating posts
 * Following Single Responsibility Principle
 */
class Posts_Scanner_Service {

    /**
     * Meta key for last scan timestamp
     */
    const META_KEY_LAST_SCAN = 'wpmudev_test_last_scan';

    /**
     * Scan posts and update meta
     *
     * @param array $post_types Post types to scan
     * @param int   $batch_size Number of posts to process in each batch
     * @param int   $offset     Offset for pagination
     * @return array Results of the scan
     */
    public function scan_posts( $post_types = array( 'post', 'page' ), $batch_size = 50, $offset = 0 ) {
        $args = array(
            'post_type'      => $post_types,
            'post_status'    => 'publish',
            'posts_per_page' => $batch_size,
            'offset'         => $offset,
            'fields'         => 'ids',
            'no_found_rows'  => false,
        );

        $query = new \WP_Query( $args );
        $processed = 0;
        $errors = array();

        if ( $query->have_posts() ) {
            foreach ( $query->posts as $post_id ) {
                try {
                    $this->update_post_meta( $post_id );
                    $processed++;
                } catch ( Exception $e ) {
                    $errors[] = sprintf(
                        __( 'Failed to update post ID %d: %s', 'wpmudev-plugin-test' ),
                        $post_id,
                        $e->getMessage()
                    );
                }
            }
        }

        return array(
            'processed'    => $processed,
            'total_found'  => $query->found_posts,
            'errors'       => $errors,
            'has_more'     => ( $offset + $batch_size ) < $query->found_posts,
            'next_offset'  => $offset + $batch_size,
        );
    }

    /**
     * Update post meta with current timestamp
     *
     * @param int $post_id Post ID
     * @throws Exception If update fails
     */
    private function update_post_meta( $post_id ) {
        $current_time = current_time( 'timestamp' );
        
        $result = update_post_meta( $post_id, self::META_KEY_LAST_SCAN, $current_time );
        
        if ( false === $result ) {
            throw new Exception( sprintf(
                __( 'Failed to update meta for post ID %d', 'wpmudev-plugin-test' ),
                $post_id
            ) );
        }

        // Log the action for debugging
        do_action( 'wpmudev_post_scanned', $post_id, $current_time );
    }

    /**
     * Get total count of posts to be scanned
     *
     * @param array $post_types Post types to count
     * @return int Total count
     */
    public function get_total_posts_count( $post_types = array( 'post', 'page' ) ) {
        $args = array(
            'post_type'   => $post_types,
            'post_status' => 'publish',
            'fields'      => 'ids',
        );

        $query = new \WP_Query( $args );
        return $query->found_posts;
    }

    /**
     * Get information about the last scan
     *
     * @return array Last scan information
     */
    public function get_last_scan_info() {
        $last_scan_option = get_option( 'wpmudev_last_scan_info', array() );
        
        return wp_parse_args( $last_scan_option, array(
            'timestamp'     => 0,
            'total_scanned' => 0,
            'post_types'    => array(),
            'duration'      => 0,
        ) );
    }

    /**
     * Save information about completed scan
     *
     * @param array $scan_info Scan information to save
     */
    public function save_scan_info( $scan_info ) {
        $default_info = array(
            'timestamp'     => current_time( 'timestamp' ),
            'total_scanned' => 0,
            'post_types'    => array(),
            'duration'      => 0,
        );

        $scan_info = wp_parse_args( $scan_info, $default_info );
        update_option( 'wpmudev_last_scan_info', $scan_info );
    }

    /**
     * Get posts that have been scanned (for testing/verification)
     *
     * @param array $post_types Post types to check
     * @param int   $limit      Limit results
     * @return array Array of post IDs with scan timestamps
     */
    public function get_scanned_posts( $post_types = array( 'post', 'page' ), $limit = 100 ) {
        global $wpdb;

        $post_types_placeholder = implode( ',', array_fill( 0, count( $post_types ), '%s' ) );
        
        $query = $wpdb->prepare(
            "SELECT p.ID, pm.meta_value as scan_timestamp 
             FROM {$wpdb->posts} p 
             INNER JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id 
             WHERE p.post_type IN ($post_types_placeholder) 
             AND p.post_status = 'publish' 
             AND pm.meta_key = %s 
             ORDER BY pm.meta_value DESC 
             LIMIT %d",
            array_merge( $post_types, array( self::META_KEY_LAST_SCAN, $limit ) )
        );

        return $wpdb->get_results( $query );
    }
}