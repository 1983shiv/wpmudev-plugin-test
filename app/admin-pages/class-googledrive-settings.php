<?php
/**
 * Google Drive test block.
 *
 * @link          https://wpmudev.com/
 * @since         1.0.0
 *
 * @author        WPMUDEV (https://wpmudev.com)
 * @package       WPMUDEV\PluginTest
 *
 * @copyright (c) 2025, Incsub (http://incsub.com)
 */

namespace WPMUDEV\PluginTest\App\Admin_Pages;

// Abort if called directly.
defined( 'WPINC' ) || die;

use WPMUDEV\PluginTest\Base;

class Google_Drive extends Base {
    /**
     * The page title.
     *
     * @var string
     */
    private $page_title;

    /**
     * The page slug.
     *
     * @var string
     */
    private $page_slug = 'wpmudev_plugintest_drive';

    /**
     * Page hook suffix for proper script loading
     *
     * @var string
     */
    private $page_hook;

    /**
     * Google Drive auth credentials.
     *
     * @since 1.0.0
     *
     * @var array
     */
    private $creds = array();

    /**
     * Option name for credentials (reusing the same as original auth).
     *
     * @var string
     */
    private $option_name = 'wpmudev_plugin_tests_auth';

    /**
     * Page Assets.
     *
     * @var array
     */
    private $page_scripts = array();

    /**
     * Assets version.
     *
     * @var string
     */
    private $assets_version = '';

    /**
     * A unique string id to be used in markup and jsx.
     *
     * @var string
     */
    private $unique_id = '';

    /**
     * Initializes the page.
     *
     * @return void
     * @since 1.0.0
     */
    public function init() {
        $this->page_title     = __( 'Google Drive Test', 'wpmudev-plugin-test' );
        $this->creds          = get_option( $this->option_name, array() );
        $this->assets_version = ! empty( $this->script_data( 'version' ) ) ? $this->script_data( 'version' ) : WPMUDEV_PLUGINTEST_VERSION;
        $this->unique_id      = "wpmudev_plugintest_drive_main_wrap-{$this->assets_version}";

        add_action( 'admin_menu', array( $this, 'register_admin_page' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
        // Add body class to admin pages.
        add_filter( 'admin_body_class', array( $this, 'admin_body_classes' ) );

		// ADDED: Handle OAuth callback
    	add_action( 'admin_init', array( $this, 'handle_oauth_callback' ) );
    }

	/**
	 * Handle OAuth callback from Google
	 */
	public function handle_oauth_callback() {
		// Check if this is our page and has auth success
		if ( ! isset( $_GET['page'] ) || $_GET['page'] !== $this->page_slug ) {
			return;
		}

		// Check for auth success parameter
		if ( isset( $_GET['auth'] ) && $_GET['auth'] === 'success' ) {
			// Add JavaScript to close popup and refresh parent
			add_action( 'admin_footer', array( $this, 'close_popup_script' ) );
		}

		// Handle OAuth callback with authorization code
		if ( isset( $_GET['action'] ) && $_GET['action'] === 'oauth_callback' && isset( $_GET['code'] ) ) {
			$this->process_oauth_callback( $_GET['code'] );
		}
	}

	/**
	 * Process OAuth callback with authorization code
	 */
	private function process_oauth_callback( $auth_code ) {
		try {
			// You would typically exchange the auth code for access token here
			// For now, just redirect to success
			wp_redirect( admin_url( 'admin.php?page=' . $this->page_slug . '&auth=success' ) );
			exit;
		} catch ( Exception $e ) {
			wp_redirect( admin_url( 'admin.php?page=' . $this->page_slug . '&auth=error&message=' . urlencode( $e->getMessage() ) ) );
			exit;
		}
	}

	/**
	 * Add script to close popup window
	 */
	public function close_popup_script() {
		?>
		<script type="text/javascript">
		(function() {
			// Close popup and refresh parent window
			if (window.opener) {
				// Notify parent window that auth is complete
				try {
					window.opener.postMessage({ 
						type: 'google_auth_success', 
						success: true 
					}, '*');
				} catch (e) {
					console.log('Could not notify parent window');
				}
				
				// Close popup
				window.close();
			}
		})();
		</script>
		<?php
	}

    /**
     * Register admin page
     */
    public function register_admin_page() {
        $this->page_hook = add_menu_page(
            __( 'Google Drive Test', 'wpmudev-plugin-test' ),
            $this->page_title,
            'manage_options',
            $this->page_slug,
            array( $this, 'callback' ),
            'dashicons-cloud',
            7
        );

        // Prepare assets only when our page loads
        add_action( 'load-' . $this->page_hook, array( $this, 'prepare_assets' ) );
    }

    /**
     * The admin page callback method.
     *
     * @return void
     */
    public function callback() {
        $this->view();
    }

    /**
     * Prepares assets.
     *
     * @return void
     */
    public function prepare_assets() {
		if ( ! is_array( $this->page_scripts ) ) {
			$this->page_scripts = array();
		}

		$handle = 'wpmudev_plugintest_drivepage';
		
		// Using YOUR asset paths and constants
		$src       = WPMUDEV_PLUGINTEST_URL . 'assets/js/drivetestpage.min.js';
		$style_src = WPMUDEV_PLUGINTEST_URL . 'assets/css/drivetestpage.min.css';
		
		// Get dependencies from asset file
		$dependencies = ! empty( $this->script_data( 'dependencies' ) )
			? $this->script_data( 'dependencies' )
			: array(
				'react',
				'wp-element',
				'wp-i18n',
				'wp-components',
				'wp-api-fetch',
				'wp-data',
				'wp-polyfill',
			);

		$this->page_scripts[ $handle ] = array(
			'src'       => $src,
			'style_src' => $style_src,
			'deps'      => $dependencies,
			'ver'       => $this->assets_version,
			'strategy'  => true,
			'localize'  => array(
				'dom_element_id'         => $this->unique_id,
				// REST API configuration
				'restUrl'                => rest_url(),
				'restRoot'               => esc_url_raw( rest_url() ),
				'apiUrl'                 => home_url( '/wp-json/' ),
				'nonce'                  => wp_create_nonce( 'wp_rest' ),
				// Existing endpoints
				'restEndpointSave'       => 'wpmudev/v1/drive/save-credentials',
				'restEndpointAuth'       => 'wpmudev/v1/drive/auth',
				'restEndpointFiles'      => 'wpmudev/v1/drive/files',
				'restEndpointUpload'     => 'wpmudev/v1/drive/upload',
				'restEndpointDownload'   => 'wpmudev/v1/drive/download',
				'restEndpointCreate'     => 'wpmudev/v1/drive/create-folder',
				'restEndpointAuthStatus' => 'wpmudev/v1/drive/auth-status',
				// FIXED: Ensure these are proper booleans
				'authStatus'             => (bool) $this->get_auth_status(),
				'hasCredentials'         => (bool) $this->has_valid_credentials(),
				'redirectUri'            => $this->get_redirect_uri(),
				// Translatable strings
				'strings'                => array(
					'confirmDelete'           => __( 'Are you sure you want to delete this file?', 'wpmudev-plugin-test' ),
					'uploadSuccess'           => __( 'File uploaded successfully', 'wpmudev-plugin-test' ),
					'uploadError'             => __( 'Upload failed', 'wpmudev-plugin-test' ),
					'networkError'            => __( 'Network error. Please try again.', 'wpmudev-plugin-test' ),
					'authRequired'            => __( 'Authentication required', 'wpmudev-plugin-test' ),
					'invalidFile'             => __( 'Invalid file type or size', 'wpmudev-plugin-test' ),
					'redirectUriInstruction'  => sprintf(
						__( 'Please use this URL %s in your Google API\'s Authorized redirect URIs field.', 'wpmudev-plugin-test' ),
						$this->get_redirect_uri()
					),
				),
			),
		);
	}

    /**
     * Checks if user is authenticated with Google Drive.
     *
     * @return bool
     */
    private function get_auth_status() {
        // Check for access token and expiry time using direct option checks
        $access_token = get_option( 'wpmudev_drive_access_token', '' );
        $expires_at   = get_option( 'wpmudev_drive_token_expires', 0 );
        $refresh_token = get_option( 'wpmudev_drive_refresh_token', '' );
        
        // If we have an access token that hasn't expired, we're authenticated
        if ( ! empty( $access_token ) && time() < (int) $expires_at ) {
            return true;
        }
        
        // If we have a refresh token, we can potentially refresh the access token
        if ( ! empty( $refresh_token ) ) {
            return true;
        }
        
        return false;
    }

    /**
     * Get redirect URI for OAuth
     */
    private function get_redirect_uri() {
        return admin_url( 'admin.php?page=' . $this->page_slug . '&action=oauth_callback' );
    }

    /**
     * Check if credentials are configured
     */
    private function has_valid_credentials() {
        return ! empty( $this->creds['client_id'] ) && ! empty( $this->creds['client_secret'] );
    }

    /**
     * Gets assets data for given key.
     *
     * @param string $key
     *
     * @return string|array
     */
    protected function script_data( string $key = '' ) {
        $raw_script_data = $this->raw_script_data();

        return ! empty( $key ) && ! empty( $raw_script_data[ $key ] ) ? $raw_script_data[ $key ] : '';
    }

    /**
     * Gets the script data from assets php file.
     *
     * @return array
     */
    protected function raw_script_data(): array {
        static $script_data = null;

        // Updated path to match your build structure
        $asset_file_path = WPMUDEV_PLUGINTEST_DIR . 'build/googledrive-page/main.asset.php';
        
        if ( is_null( $script_data ) && file_exists( $asset_file_path ) ) {
            $script_data = include $asset_file_path;
        }

        return (array) $script_data;
    }

    /**
     * Enqueue assets - Enhanced version with proper page checking
     *
     * @param string $hook Current admin page hook
     * @return void
     */
    public function enqueue_assets( $hook ) {
        // Only load scripts on our specific page
        if ( $hook !== $this->page_hook ) {
            return;
        }

		// ADDED: Ensure wp-api-fetch is configured properly
    	wp_enqueue_script( 'wp-api-fetch' );

        // Set script translations for i18n
        if ( ! empty( $this->page_scripts ) ) {
            foreach ( $this->page_scripts as $handle => $page_script ) {
                wp_register_script(
                    $handle,
                    $page_script['src'],
                    $page_script['deps'],
                    $page_script['ver'],
                    $page_script['strategy']
                );

                // Set script translations for internationalization
                wp_set_script_translations( $handle, 'wpmudev-plugin-test', WPMUDEV_PLUGINTEST_DIR . 'languages' );

                if ( ! empty( $page_script['localize'] ) ) {
                    wp_localize_script( $handle, 'wpmudevDriveTest', $page_script['localize'] );
                }

                wp_enqueue_script( $handle );

                if ( ! empty( $page_script['style_src'] ) ) {
                    wp_enqueue_style( $handle, $page_script['style_src'], array(), $this->assets_version );
                }
            }
        }
		// ADDED: Ensure WordPress REST API settings are available
		wp_localize_script( 'wp-api-fetch', 'wpApiSettings', array(
			'root'  => esc_url_raw( rest_url() ),
			'nonce' => wp_create_nonce( 'wp_rest' ),
		) );
    }

    /**
     * Prints the wrapper element which React will use as root.
     *
     * @return void
     */
    protected function view() {
        echo '<div id="' . esc_attr( $this->unique_id ) . '" class="sui-wrap"></div>';
    }

    /**
     * Adds the SUI class on markup body.
     *
     * @param string $classes
     *
     * @return string
     */
    public function admin_body_classes( $classes = '' ) {
        if ( ! function_exists( 'get_current_screen' ) ) {
            return $classes;
        }

        $current_screen = get_current_screen();

        if ( empty( $current_screen->id ) || ! strpos( $current_screen->id, $this->page_slug ) ) {
            return $classes;
        }

        $classes .= ' sui-' . str_replace( '.', '-', WPMUDEV_PLUGINTEST_SUI_VERSION ) . ' ';

        return $classes;
    }
}