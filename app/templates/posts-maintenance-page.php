<?php
/**
 * Posts Maintenance Admin Page Template
 *
 * @package WPMUDEV\PluginTest
 * @since 1.0.0
 */

defined( 'WPINC' ) || die;
?>

<div class="wrap">
    <h1><?php esc_html_e( 'Posts Maintenance', 'wpmudev-plugin-test' ); ?></h1>
    
    <div class="wpmudev-posts-maintenance">
        
        <!-- Scan Configuration -->
        <div class="postbox">
            <h2 class="hndle"><?php esc_html_e( 'Scan Configuration', 'wpmudev-plugin-test' ); ?></h2>
            <div class="inside">
                <form id="wpmudev-scan-form">
                    <table class="form-table">
                        <tr>
                            <th scope="row">
                                <label for="post-types"><?php esc_html_e( 'Post Types to Scan', 'wpmudev-plugin-test' ); ?></label>
                            </th>
                            <td>
                                <?php foreach ( $available_post_types as $post_type => $label ) : ?>
                                    <label>
                                        <input type="checkbox" name="post_types[]" value="<?php echo esc_attr( $post_type ); ?>" 
                                               <?php checked( in_array( $post_type, array( 'post', 'page' ) ) ); ?>>
                                        <?php echo esc_html( $label ); ?>
                                    </label><br>
                                <?php endforeach; ?>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="batch-size"><?php esc_html_e( 'Batch Size', 'wpmudev-plugin-test' ); ?></label>
                            </th>
                            <td>
                                <input type="number" id="batch-size" name="batch_size" value="50" min="10" max="200" step="10">
                                <p class="description"><?php esc_html_e( 'Number of posts to process in each batch (10-200)', 'wpmudev-plugin-test' ); ?></p>
                            </td>
                        </tr>
                    </table>
                    
                    <p class="submit">
                        <button type="submit" class="button button-primary" id="start-scan-btn" <?php disabled( $is_scan_running ); ?>>
                            <?php esc_html_e( 'Start Scan', 'wpmudev-plugin-test' ); ?>
                        </button>
                        <button type="button" class="button button-secondary" id="stop-scan-btn" 
                                <?php disabled( ! $is_scan_running ); ?>>
                            <?php esc_html_e( 'Stop Scan', 'wpmudev-plugin-test' ); ?>
                        </button>
                    </p>
                </form>
            </div>
        </div>

        <!-- Progress Display -->
        <div class="postbox" id="progress-container" <?php echo $is_scan_running ? '' : 'style="display:none;"'; ?>>
            <h2 class="hndle"><?php esc_html_e( 'Scan Progress', 'wpmudev-plugin-test' ); ?></h2>
            <div class="inside">
                <div id="progress-bar-container">
                    <div id="progress-bar" style="width: 0%; background: #0073aa; height: 20px; border-radius: 3px;"></div>
                </div>
                <p id="progress-text"><?php esc_html_e( 'Preparing to scan...', 'wpmudev-plugin-test' ); ?></p>
                <div id="progress-details" style="margin-top: 10px;"></div>
            </div>
        </div>

        <!-- Last Scan Information -->
        <?php if ( ! empty( $last_scan_info['timestamp'] ) ) : ?>
        <div class="postbox">
            <h2 class="hndle"><?php esc_html_e( 'Last Scan Information', 'wpmudev-plugin-test' ); ?></h2>
            <div class="inside">
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Date', 'wpmudev-plugin-test' ); ?></th>
                        <td><?php echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $last_scan_info['timestamp'] ) ); ?></td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Posts Scanned', 'wpmudev-plugin-test' ); ?></th>
                        <td><?php echo esc_html( number_format( $last_scan_info['total_scanned'] ) ); ?></td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Post Types', 'wpmudev-plugin-test' ); ?></th>
                        <td><?php echo esc_html( implode( ', ', $last_scan_info['post_types'] ) ); ?></td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Duration', 'wpmudev-plugin-test' ); ?></th>
                        <td><?php echo esc_html( human_time_diff( 0, $last_scan_info['duration'] ) ); ?></td>
                    </tr>
                </table>
            </div>
        </div>
        <?php endif; ?>

        <!-- Scheduled Tasks -->
        <div class="postbox">
            <h2 class="hndle"><?php esc_html_e( 'Scheduled Tasks', 'wpmudev-plugin-test' ); ?></h2>
            <div class="inside">
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Daily Automatic Scan', 'wpmudev-plugin-test' ); ?></th>
                        <td>
                            <?php if ( $next_scheduled ) : ?>
                                <?php printf(
                                    esc_html__( 'Next scan scheduled for: %s', 'wpmudev-plugin-test' ),
                                    '<strong>' . esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $next_scheduled ) ) . '</strong>'
                                ); ?>
                            <?php else : ?>
                                <span class="error"><?php esc_html_e( 'No automatic scan scheduled', 'wpmudev-plugin-test' ); ?></span>
                            <?php endif; ?>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Notices -->
        <div id="wpmudev-notices" class="notice-container"></div>
    </div>
</div>