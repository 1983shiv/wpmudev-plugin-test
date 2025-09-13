(function($) {
    'use strict';

    /**
     * Posts Maintenance Admin Interface
     */
    const PostsMaintenance = {
        
        /**
         * Progress polling interval
         */
        progressInterval: null,

        /**
         * Initialize the admin interface
         */
        init: function() {
            this.bindEvents();
            this.checkCurrentProgress();
        },

        /**
         * Bind event handlers
         */
        bindEvents: function() {
            $('#wpmudev-scan-form').on('submit', this.handleStartScan.bind(this));
            $('#stop-scan-btn').on('click', this.handleStopScan.bind(this));
        },

        /**
         * Handle start scan form submission
         */
        handleStartScan: function(e) {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const postTypes = formData.getAll('post_types[]');
            const batchSize = formData.get('batch_size');

            if (postTypes.length === 0) {
                this.showNotice('Please select at least one post type to scan.', 'error');
                return;
            }

            this.startScan(postTypes, batchSize);
        },

        /**
         * Start the scan process
         */
        // startScan: function(postTypes, batchSize) {
        //     const data = {
        //         action: 'wpmudev_scan_posts',
        //         nonce: wpmudevPostsMaintenance.nonce,
        //         post_types: postTypes,
        //         batch_size: batchSize
        //     };

        //     $.post(wpmudevPostsMaintenance.ajaxUrl, data)
        //         .done((response) => {
        //             if (response.success) {
        //                 this.showNotice(response.data.message, 'success');
        //                 this.showProgressContainer();
        //                 this.startProgressPolling();
        //                 this.updateScanButtons(true);
        //             } else {
        //                 this.showNotice(response.data.message, 'error');
        //             }
        //         })
        //         .fail(() => {
        //             this.showNotice(wpmudevPostsMaintenance.strings.scanError, 'error');
        //         });
        // },

        startScan: function(postTypes, batchSize) {
            const data = {
                action: 'wpmudev_scan_posts',
                nonce: wpmudevPostsMaintenance.nonce,
                post_types: postTypes,
                batch_size: batchSize
            };

            // FIXED: Better error handling
            $.ajax({
                url: wpmudevPostsMaintenance.ajaxUrl,
                type: 'POST',
                data: data,
                timeout: 30000,
                success: (response) => {
                    if (response.success) {
                        this.showNotice(response.data.message, 'success');
                        this.showProgressContainer();
                        this.startProgressPolling();
                        this.updateScanButtons(true);
                    } else {
                        console.error('Scan start failed:', response);
                        const message = response.data && response.data.message ? 
                            response.data.message : 
                            'Failed to start scan';
                        this.showNotice(message, 'error');
                    }
                },
                error: (xhr, status, error) => {
                    console.error('AJAX Scan Error Details:', {
                        status: xhr.status,
                        statusText: xhr.statusText,
                        responseText: xhr.responseText,
                        error: error
                    });
                    
                    let errorMessage = 'Failed to start scan';
                    if (xhr.responseText) {
                        try {
                            const errorResponse = JSON.parse(xhr.responseText);
                            if (errorResponse.data && errorResponse.data.message) {
                                errorMessage = errorResponse.data.message;
                            }
                        } catch (e) {
                            // responseText is not JSON, use default message
                        }
                    }
                    
                    this.showNotice(errorMessage, 'error');
                }
            });
        },
        /**
         * Handle stop scan
         */
        handleStopScan: function() {
            if (!confirm(wpmudevPostsMaintenance.strings.confirmStop)) {
                return;
            }

            const data = {
                action: 'wpmudev_stop_scan',
                nonce: wpmudevPostsMaintenance.nonce
            };

            $.post(wpmudevPostsMaintenance.ajaxUrl, data)
                .done((response) => {
                    if (response.success) {
                        this.showNotice(response.data.message, 'success');
                        this.stopProgressPolling();
                        this.hideProgressContainer();
                        this.updateScanButtons(false);
                    } else {
                        this.showNotice(response.data.message, 'error');
                    }
                })
                .fail(() => {
                    this.showNotice(wpmudevPostsMaintenance.strings.scanError, 'error');
                });
        },

        /**
         * Start polling for progress updates
         */
        startProgressPolling: function() {
            this.progressInterval = setInterval(() => {
                this.updateProgress();
            }, 2000);
        },

        /**
         * Stop polling for progress updates
         */
        stopProgressPolling: function() {
            if (this.progressInterval) {
                clearInterval(this.progressInterval);
                this.progressInterval = null;
            }
        },

        /**
         * Update progress display
         */
        updateProgress: function() {
            const data = {
                action: 'wpmudev_get_scan_progress',
                nonce: wpmudevPostsMaintenance.nonce
            };
            
            // FIXED: Better error handling with detailed logging
            $.ajax({
                url: wpmudevPostsMaintenance.ajaxUrl,
                type: 'GET',
                data: data,
                timeout: 10000,
                success: (response) => {
                    if (response.success) {
                        this.displayProgress(response.data);
                    } else {
                        console.error('Progress update failed:', response);
                        // Show user-friendly message for actual errors
                        if (response.data && response.data.message) {
                            this.showNotice(response.data.message, 'error');
                        }
                    }
                },
                error: (xhr, status, error) => {
                    console.error('AJAX Progress Error Details:', {
                        status: xhr.status,
                        statusText: xhr.statusText,
                        responseText: xhr.responseText,
                        error: error,
                        readyState: xhr.readyState
                    });
                    
                    // Only show error to user if it's a real failure
                    if (xhr.status !== 0 && xhr.status !== 200) {
                        this.showNotice('Failed to get scan progress', 'error');
                    }
                }
            });
        },

        /**
         * Display progress information
         */
        // displayProgress: function(progress) {
        //     const progressBar = $('#progress-bar');
        //     const progressText = $('#progress-text');
        //     const progressDetails = $('#progress-details');

        //     // Update progress bar
        //     progressBar.css('width', progress.progress + '%');

        //     // Update progress text
        //     let statusText = '';
        //     switch (progress.status) {
        //         case 'running':
        //             statusText = wpmudevPostsMaintenance.strings.processingPosts;
        //             break;
        //         case 'completed':
        //             statusText = wpmudevPostsMaintenance.strings.scanCompleted;
        //             this.stopProgressPolling();
        //             this.updateScanButtons(false);
        //             this.showNotice('Scan completed successfully!', 'success');
        //             // REMOVED: setTimeout(() => { location.reload(); }, 2000);
        //             break;
        //         case 'stopped':
        //             statusText = wpmudevPostsMaintenance.strings.scanStopped;
        //             this.stopProgressPolling();
        //             this.updateScanButtons(false);
        //             break;
        //         case 'error':
        //             statusText = wpmudevPostsMaintenance.strings.scanError;
        //             this.stopProgressPolling();
        //             this.updateScanButtons(false);
        //             break;
        //     }

        //     progressText.text(statusText);

        //     // Update details
        //     const detailsHtml = `
        //         <strong>Progress:</strong> ${progress.processed} / ${progress.total} posts (${progress.progress}%)
        //         ${progress.errors.length > 0 ? '<br><strong>Errors:</strong> ' + progress.errors.length : ''}
        //     `;
        //     progressDetails.html(detailsHtml);
        // },
        displayProgress: function(progress) {
            const progressBar = $('#progress-bar');
            const progressText = $('#progress-text');
            const progressDetails = $('#progress-details');

            // Update progress bar
            progressBar.css('width', progress.progress + '%');

            // Update progress text
            let statusText = '';
            switch (progress.status) {
                case 'running':
                    statusText = wpmudevPostsMaintenance.strings.processingPosts;
                    break;
                case 'completed':
                    statusText = wpmudevPostsMaintenance.strings.scanCompleted;
                    this.stopProgressPolling();
                    this.updateScanButtons(false);
                    this.showNotice('Scan completed successfully!', 'success');
                    
                    // Hide progress UI after showing completion
                    setTimeout(() => {
                        this.hideProgressContainer();
                        this.resetProgressDisplay();
                        // Clear the completed status
                        this.clearScanStatus();
                    }, 3000);
                    break;
                case 'stopped':
                    statusText = wpmudevPostsMaintenance.strings.scanStopped;
                    this.stopProgressPolling();
                    this.updateScanButtons(false);
                    setTimeout(() => {
                        this.hideProgressContainer();
                        this.resetProgressDisplay();
                    }, 2000);
                    break;
                case 'error':
                    statusText = wpmudevPostsMaintenance.strings.scanError;
                    this.stopProgressPolling();
                    this.updateScanButtons(false);
                    setTimeout(() => {
                        this.hideProgressContainer();
                        this.resetProgressDisplay();
                    }, 5000);
                    break;
            }

            progressText.text(statusText);

            // Update details
            const detailsHtml = `
                <strong>Progress:</strong> ${progress.processed} / ${progress.total} posts (${progress.progress}%)
                ${progress.errors.length > 0 ? '<br><strong>Errors:</strong> ' + progress.errors.length : ''}
            `;
            progressDetails.html(detailsHtml);
        },

        /**
         * Reset progress display to initial state
         */
        resetProgressDisplay: function() {
            $('#progress-bar').css('width', '0%');
            $('#progress-text').text('');
            $('#progress-details').html('');
        },

        /**
         * Clear scan status on backend
         */
        clearScanStatus: function() {
            $.post(wpmudevPostsMaintenance.ajaxUrl, {
                action: 'wpmudev_clear_scan_status',
                nonce: wpmudevPostsMaintenance.nonce
            });
        },
        /**
         * Check current progress on page load
         */
        checkCurrentProgress: function() {
            this.updateProgress();
        },

        /**
         * Show progress container
         */
        showProgressContainer: function() {
            $('#progress-container').show();
        },

        /**
         * Hide progress container
         */
        hideProgressContainer: function() {
            $('#progress-container').hide();
        },

        /**
         * Update scan button states
         */
        updateScanButtons: function(isScanning) {
            $('#start-scan-btn').prop('disabled', isScanning);
            $('#stop-scan-btn').prop('disabled', !isScanning);
        },

        /**
         * Show admin notice
         */
        showNotice: function(message, type = 'success') {
            const noticeClass = `notice notice-${type} is-dismissible`;
            const noticeHtml = `
                <div class="${noticeClass}">
                    <p>${message}</p>
                    <button type="button" class="notice-dismiss">
                        <span class="screen-reader-text">Dismiss this notice.</span>
                    </button>
                </div>
            `;

            const $notice = $(noticeHtml);
            $('#wpmudev-notices').append($notice);

            // Auto-dismiss after 5 seconds
            setTimeout(() => {
                $notice.fadeOut(() => {
                    $notice.remove();
                });
            }, 5000);

            // Handle manual dismiss
            $notice.on('click', '.notice-dismiss', function() {
                $notice.fadeOut(() => {
                    $notice.remove();
                });
            });
        }
    };

    // Initialize when document is ready
    $(document).ready(function() {
        PostsMaintenance.init();
    });

})(jQuery);