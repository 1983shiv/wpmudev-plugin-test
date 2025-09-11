<?php
/**
 * Service Container for Dependency Injection
 *
 * @package WPMUDEV\PluginTest
 */

namespace WPMUDEV\PluginTest;

use Exception;

// Abort if called directly.
defined( 'WPINC' ) || die;

class Service_Container {
    
    /**
     * Registered services
     *
     * @var array
     */
    private $services = array();
    
    /**
     * Service bindings
     *
     * @var array
     */
    private $bindings = array();
    
    /**
     * Singleton instances
     *
     * @var array
     */
    private $singletons = array();
    
    /**
     * Bind a service
     *
     * @param string $abstract
     * @param callable|string $concrete
     * @param bool $singleton
     */
    public function bind( $abstract, $concrete, $singleton = false ) {
        $this->bindings[ $abstract ] = array(
            'concrete' => $concrete,
            'singleton' => $singleton,
        );
    }
    
    /**
     * Register a singleton service
     *
     * @param string $abstract
     * @param callable|string $concrete
     */
    public function singleton( $abstract, $concrete ) {
        $this->bind( $abstract, $concrete, true );
    }
    
    /**
     * Make a service instance
     *
     * @param string $abstract
     * @return mixed
     * @throws Exception
     */
    public function make( $abstract ) {
        // Return singleton if already instantiated
        if ( isset( $this->singletons[ $abstract ] ) ) {
            return $this->singletons[ $abstract ];
        }
        
        // Check if service is bound
        if ( ! isset( $this->bindings[ $abstract ] ) ) {
            throw new Exception( "Service {$abstract} not found in container" );
        }
        
        $binding = $this->bindings[ $abstract ];
        $concrete = $binding['concrete'];
        
        if ( is_callable( $concrete ) ) {
            $instance = $concrete( $this );
        } elseif ( is_string( $concrete ) && class_exists( $concrete ) ) {
            $instance = new $concrete();
        } else {
            throw new Exception( "Unable to resolve service {$abstract}" );
        }
        
        // Store singleton
        if ( $binding['singleton'] ) {
            $this->singletons[ $abstract ] = $instance;
        }
        
        return $instance;
    }
    
    /**
     * Check if service is bound
     *
     * @param string $abstract
     * @return bool
     */
    public function bound( $abstract ) {
        return isset( $this->bindings[ $abstract ] );
    }
}
