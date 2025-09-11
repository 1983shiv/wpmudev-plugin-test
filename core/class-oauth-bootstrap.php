<?php
/**
 * OAuth Bootstrap Class
 */

namespace WPMUDEV\PluginTest;

use WPMUDEV\PluginTest\Service_Container;
use WPMUDEV\PluginTest\Services\Encryption_Service;
use WPMUDEV\PluginTest\Services\Logger_Service;
use WPMUDEV\PluginTest\Services\Google_Auth_Service;
use WPMUDEV\PluginTest\Repositories\WP_Token_Repository;

class OAuth_Bootstrap {

    /**
     * Service container instance
     */
    private $container;

    /**
     * Initialize OAuth services
     */
    public function init() {
        $this->setup_service_container();
        $this->bind_services();
        $this->make_container_global();
    }

    /**
     * Setup service container
     */
    private function setup_service_container() {
        $this->container = new Service_Container();
    }

    /**
     * Bind all services to container
     */
    private function bind_services() {
        // Bind encryption service
        $this->container->singleton( 'encryption_service', function() {
            return new Encryption_Service();
        });

        // Bind logger service
        $this->container->singleton( 'logger_service', function() {
            return new Logger_Service();
        });

        // Bind token repository (depends on encryption service)
        $this->container->singleton( 'token_repository', function( $container ) {
            return new WP_Token_Repository( $container->make( 'encryption_service' ) );
        });

        // Bind auth service (CORRECT parameter order: token_repository, logger)
        $this->container->singleton( 'auth_service', function( $container ) {
            return new Google_Auth_Service(
                $container->make( 'token_repository' ),  // First parameter
                $container->make( 'logger_service' )     // Second parameter
            );
        });
    }

    /**
     * Make container globally accessible
     */
    private function make_container_global() {
        global $wpmudev_service_container;
        $wpmudev_service_container = $this->container;
    }

    /**
     * Get container instance
     */
    public function get_container() {
        return $this->container;
    }
}