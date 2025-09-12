import { createRoot, render, StrictMode, useState, useEffect, createInterpolateElement } from '@wordpress/element';
import { Button, TextControl, Spinner, Notice, ProgressBar } from '@wordpress/components';
import { __ } from '@wordpress/i18n';

import "./scss/style.scss";

const domElement = document.getElementById( window.wpmudevDriveTest.dom_element_id );

const WPMUDEV_DriveTest = () => {
    // State management
    const [isAuthenticated, setIsAuthenticated] = useState(window.wpmudevDriveTest.authStatus || false);
    const [hasCredentials, setHasCredentials] = useState(window.wpmudevDriveTest.hasCredentials || false);
    const [showCredentials, setShowCredentials] = useState(!window.wpmudevDriveTest.hasCredentials);
    // const [isAuthenticated, setIsAuthenticated] = useState(Boolean(window.wpmudevDriveTest.authStatus));
    // const [hasCredentials, setHasCredentials] = useState(Boolean(window.wpmudevDriveTest.hasCredentials));
    // const [showCredentials, setShowCredentials] = useState(!Boolean(window.wpmudevDriveTest.hasCredentials));

    const [nextPageToken, setNextPageToken] = useState(null);
    const [hasMoreFiles, setHasMoreFiles] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [files, setFiles] = useState([]);
    const [uploadFile, setUploadFile] = useState(null);
    const [folderName, setFolderName] = useState('');
    const [notice, setNotice] = useState({ message: '', type: '' });
    const [credentials, setCredentials] = useState({
        clientId: '',
        clientSecret: ''
    });
    const [uploadProgress, setUploadProgress] = useState(null);
    const [authStatusLoading, setAuthStatusLoading] = useState(false);

    // Add this before the component definition:
    if (window.wpmudevDriveTest && !window.wpmudevDriveTest.restUrl) {
        window.wpmudevDriveTest.restUrl = window.location.origin + '/wpmudev1/wp-json/';
        window.wpmudevDriveTest.nonce = window.wpmudevDriveTest.nonce || '';
    }



    // Call it in useEffect:
    useEffect(() => {        
        // ADDED: Force state update based on actual values
        const actualAuthStatus = Boolean(window.wpmudevDriveTest.authStatus);
        const actualHasCredentials = Boolean(window.wpmudevDriveTest.hasCredentials);
        
        setIsAuthenticated(actualAuthStatus);
        setHasCredentials(actualHasCredentials);
        setShowCredentials(!actualHasCredentials);
        
        // Only check auth status if not already authenticated
        if (!actualAuthStatus) {
            checkAuthStatus();
        }
    }, []);
    


    // Auto-load files when authenticated
    useEffect(() => {
        if (isAuthenticated) {
            // console.log('Loading files because user is authenticated');
            loadFiles();
        }
    }, [isAuthenticated]);


    // hook to handle URL parameters on page load:
    useEffect(() => {
        // Check for auth success/error parameters in URL
        const urlParams = new URLSearchParams(window.location.search);
        const authStatus = urlParams.get('auth');
        
        if (authStatus === 'success') {
            // If this is the popup window, let the script handle it
            if (window.opener) {
                return;
            }
            
            // If this is the main window, check auth status
            setTimeout(() => {
                checkAuthStatus();
            }, 500);
            
            // Clean up URL
            const cleanUrl = window.location.pathname + '?page=' + urlParams.get('page');
            window.history.replaceState({}, document.title, cleanUrl);
        } else if (authStatus === 'error') {
            const errorMessage = urlParams.get('message') || __('Authentication failed', 'wpmudev-plugin-test');
            showNotice(decodeURIComponent(errorMessage), 'error');
            
            // Clean up URL
            const cleanUrl = window.location.pathname + '?page=' + urlParams.get('page');
            window.history.replaceState({}, document.title, cleanUrl);
        }
    }, []);

    /**
     * Show notice with auto-dismiss
     */
    const showNotice = (message, type = 'success') => {
        setNotice({ message, type });
        setTimeout(() => setNotice({ message: '', type: '' }), 5000);
    };

    /**
     * Check current authentication status
     */
    const checkAuthStatus = async () => {
        setAuthStatusLoading(true);
        try {
            const response = await fetch(`${window.wpmudevDriveTest.restUrl}wpmudev/v1/drive/auth-status`, {
                method: 'GET',
                headers: {
                    'X-WP-Nonce': window.wpmudevDriveTest.nonce,
                    'Content-Type': 'application/json',
                },
            });

            const data = await response.json();
            console.log('Auth status response:', data);
            
            if (data.success) {
                const newAuthStatus = Boolean(data.authenticated);
                const newHasCredentials = Boolean(data.has_credentials);
                
                console.log('Updating auth status:', {
                    authenticated: newAuthStatus,
                    has_credentials: newHasCredentials,
                    show_credentials: !newHasCredentials
                });
                
                setIsAuthenticated(newAuthStatus);
                setHasCredentials(newHasCredentials);
                setShowCredentials(!newHasCredentials);
            }
        } catch (error) {
            console.error('Auth status check failed:', error);
            showNotice(__('Failed to check authentication status', 'wpmudev-plugin-test'), 'error');
        } finally {
            setAuthStatusLoading(false);
        }
    };

    /**
     * Save Google Drive credentials
     */
    const handleSaveCredentials = async () => {
        if (!credentials.clientId.trim() || !credentials.clientSecret.trim()) {
            showNotice(__('Please fill in both Client ID and Client Secret', 'wpmudev-plugin-test'), 'error');
            return;
        }

        setIsLoading(true);
        try {
            // FIXED: Use wpmudevDriveTest.restUrl instead of wpApiSettings.root
            const response = await fetch(`${window.wpmudevDriveTest.restUrl}wpmudev/v1/drive/save-credentials`, {
                method: 'POST',
                headers: {
                    'X-WP-Nonce': window.wpmudevDriveTest.nonce,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    client_id: credentials.clientId,
                    client_secret: credentials.clientSecret,
                }),
            });

            const data = await response.json();
            
            if (data.success) {
                setHasCredentials(true);
                setShowCredentials(false);
                showNotice(__('Credentials saved successfully', 'wpmudev-plugin-test'), 'success');
                
                // Clear sensitive data from state
                setCredentials({ clientId: '', clientSecret: '' });
            } else {
                showNotice(data.message || __('Failed to save credentials', 'wpmudev-plugin-test'), 'error');
            }
        } catch (error) {
            console.error('Save credentials failed:', error);
            showNotice(__('Failed to save credentials', 'wpmudev-plugin-test'), 'error');
        } finally {
            setIsLoading(false);
        }
    };

    /**
     * Start Google Drive authentication
     */
    const handleAuth = async () => {
        setIsLoading(true);
        try {
            const response = await fetch(`${window.wpmudevDriveTest.restUrl}wpmudev/v1/drive/auth`, {
                method: 'POST',
                headers: {
                    'X-WP-Nonce': window.wpmudevDriveTest.nonce,
                    'Content-Type': 'application/json',
                },
            });

            const data = await response.json();
            
            if (data.success && data.auth_url) {
                // Open auth URL in a popup window
                const popup = window.open(
                    data.auth_url,
                    'google_auth',
                    'width=500,height=600,scrollbars=yes,resizable=yes'
                );

                // Listen for messages from popup
                const handleMessage = (event) => {
                    if (event.data && event.data.type === 'google_auth_success') {
                        // Remove event listener
                        window.removeEventListener('message', handleMessage);
                        
                        // Close popup if still open
                        try {
                            if (popup && !popup.closed) {
                                popup.close();
                            }
                        } catch (e) {
                            console.log('Could not check popup.closed due to CORP policy');
                        }
                        
                        // Check auth status after popup closes
                        setTimeout(() => {
                            checkAuthStatus();
                        }, 500);
                        
                        showNotice(__('Authentication completed successfully', 'wpmudev-plugin-test'), 'success');
                    }
                };

                // Add message listener
                window.addEventListener('message', handleMessage);

                // FIXED: Handle CORP policy for popup checking
                const checkClosed = setInterval(() => {
                    try {
                        if (popup.closed) {
                            clearInterval(checkClosed);
                            window.removeEventListener('message', handleMessage);
                            
                            // Check auth status after popup closes
                            setTimeout(() => {
                                checkAuthStatus();
                            }, 1000);
                        }
                    } catch (e) {
                        // If we can't check popup.closed due to CORP, rely on message listener only
                        console.log('Cannot check popup status due to CORP policy, relying on message listener');
                        // Clear interval after 60 seconds to prevent infinite checking
                        setTimeout(() => {
                            clearInterval(checkClosed);
                            window.removeEventListener('message', handleMessage);
                        }, 60000);
                    }
                }, 1000);

                showNotice(__('Please complete authentication in the popup window', 'wpmudev-plugin-test'), 'info');
            } else {
                showNotice(data.message || __('Failed to start authentication', 'wpmudev-plugin-test'), 'error');
            }
        } catch (error) {
            console.error('Auth failed:', error);
            showNotice(__('Authentication failed', 'wpmudev-plugin-test'), 'error');
        } finally {
            setIsLoading(false);
        }
    };

    /**
     * Load files from Google Drive
     */
    const loadFiles = async (pageToken = null, append = false) => {
        setIsLoading(true);
        try {
            const params = new URLSearchParams({
                page_size: 20,
                query: 'trashed=false'
            });
            
            if (pageToken) {
                params.append('page_token', pageToken);
            }

            const response = await fetch(`${window.wpmudevDriveTest.restUrl}wpmudev/v1/drive/files?${params.toString()}`, {
                method: 'GET',
                headers: {
                    'X-WP-Nonce': window.wpmudevDriveTest.nonce,
                    'Content-Type': 'application/json',
                },
            });

            const data = await response.json();
            
            if (data.success) {
                // Either replace files or append to existing files
                if (append) {
                    setFiles(prevFiles => [...prevFiles, ...(data.files || [])]);
                } else {
                    setFiles(data.files || []);
                }
                
                // Handle pagination
                if (data.pagination) {
                    setHasMoreFiles(data.pagination.hasNextPage);
                    setNextPageToken(data.pagination.nextPageToken);
                } else {
                    setHasMoreFiles(false);
                    setNextPageToken(null);
                }
            } else {
                showNotice(data.message || __('Failed to load files', 'wpmudev-plugin-test'), 'error');
            }
        } catch (error) {
            console.error('Load files failed:', error);
            showNotice(__('Failed to load files', 'wpmudev-plugin-test'), 'error');
        } finally {
            setIsLoading(false);
        }
    };

    // Add this function for loading more files:
    const loadMoreFiles = () => {
        if (nextPageToken && hasMoreFiles) {
            loadFiles(nextPageToken, true); // true = append to existing files
        }
    };

    /**
     * Upload file to Google Drive
     */
    const handleUpload = async () => {
        if (!uploadFile) {
            showNotice(__('Please select a file to upload', 'wpmudev-plugin-test'), 'error');
            return;
        }

        // Validate file size (100MB limit)
        const maxSize = 100 * 1024 * 1024; // 100MB
        if (uploadFile.size > maxSize) {
            showNotice(__('File size exceeds 100MB limit', 'wpmudev-plugin-test'), 'error');
            return;
        }

        setIsLoading(true);
        setUploadProgress({ progress: 0, message: __('Starting upload...', 'wpmudev-plugin-test') });

        try {
            const formData = new FormData();
            formData.append('file', uploadFile);

            // FIXED: Use wpmudevDriveTest.restUrl instead of wpApiSettings.root
            const response = await fetch(`${window.wpmudevDriveTest.restUrl}wpmudev/v1/drive/upload`, {
                method: 'POST',
                headers: {
                    'X-WP-Nonce': window.wpmudevDriveTest.nonce,
                },
                body: formData,
            });

            const data = await response.json();
            
            if (data.success) {
                setUploadFile(null);
                // Clear file input
                const fileInput = document.querySelector('.drive-file-input');
                if (fileInput) fileInput.value = '';
                
                showNotice(
                    __('File uploaded successfully: %s', 'wpmudev-plugin-test').replace('%s', data.file.name),
                    'success'
                );
                
                // Show upload progress details
                if (data.upload_progress && data.upload_progress.stages) {
                    setUploadProgress({
                        progress: 100,
                        message: __('Upload completed successfully', 'wpmudev-plugin-test'),
                        stages: data.upload_progress.stages
                    });
                }
                
                // Reload files list
                loadFiles();
            } else {
                showNotice(data.message || __('Upload failed', 'wpmudev-plugin-test'), 'error');
                
                // Show upload progress error details
                if (data.upload_progress) {
                    setUploadProgress({
                        progress: 0,
                        message: data.upload_progress.message || __('Upload failed', 'wpmudev-plugin-test'),
                        error: true
                    });
                }
            }
        } catch (error) {
            console.error('Upload failed:', error);
            showNotice(__('Upload failed', 'wpmudev-plugin-test'), 'error');
            setUploadProgress({
                progress: 0,
                message: __('Upload failed', 'wpmudev-plugin-test'),
                error: true
            });
        } finally {
            setIsLoading(false);
            // Clear upload progress after 3 seconds
            setTimeout(() => setUploadProgress(null), 3000);
        }
    };

    /**
     * Download file from Google Drive
     */
    const handleDownload = async (fileId, fileName) => {
        try {
            const response = await fetch(`${window.wpmudevDriveTest.restUrl}wpmudev/v1/drive/download`, {
                method: 'GET',
                headers: {
                    'X-WP-Nonce': window.wpmudevDriveTest.nonce,
                },
                body: {
                    fileId: fileId
                }
            });

            const data = await response.json();
            
            if (data.success && data.file.content) {
                // Convert base64 to blob and download
                const byteCharacters = atob(data.file.content);
                const byteNumbers = new Array(byteCharacters.length);
                for (let i = 0; i < byteCharacters.length; i++) {
                    byteNumbers[i] = byteCharacters.charCodeAt(i);
                }
                const byteArray = new Uint8Array(byteNumbers);
                const blob = new Blob([byteArray], { type: data.file.mimeType });

                // Create download link
                const url = window.URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = fileName;
                document.body.appendChild(link);
                link.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(link);

                showNotice(__('File downloaded successfully', 'wpmudev-plugin-test'), 'success');
            } else {
                showNotice(data.message || __('Download failed', 'wpmudev-plugin-test'), 'error');
            }
        } catch (error) {
            console.error('Download failed:', error);
            showNotice(__('Download failed', 'wpmudev-plugin-test'), 'error');
        }
    };

    /**
     * Create new folder in Google Drive
     */
    const handleCreateFolder = async () => {
        if (!folderName.trim()) {
            showNotice(__('Please enter a folder name', 'wpmudev-plugin-test'), 'error');
            return;
        }

        setIsLoading(true);
        try {
            const response = await fetch(`${window.wpmudevDriveTest.restUrl}wpmudev/v1/drive/create-folder`, {
                method: 'POST',
                headers: {
                    'X-WP-Nonce': window.wpmudevDriveTest.nonce,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: folderName.trim(),
                }),
            });

            const data = await response.json();
            
            if (data.success) {
                setFolderName('');
                showNotice(
                    __('Folder created successfully: %s', 'wpmudev-plugin-test').replace('%s', data.folder.name),
                    'success'
                );
                
                // Reload files list
                loadFiles();
            } else {
                showNotice(data.message || __('Failed to create folder', 'wpmudev-plugin-test'), 'error');
            }
        } catch (error) {
            console.error('Create folder failed:', error);
            showNotice(__('Failed to create folder', 'wpmudev-plugin-test'), 'error');
        } finally {
            setIsLoading(false);
        }
    };

    /**
     * Format file size for display
     */
    const formatFileSize = (bytes) => {
        if (!bytes) return '';
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    };

    /**
     * Determine file type for display
     */
    const getFileType = (mimeType) => {
        if (mimeType === 'application/vnd.google-apps.folder') {
            return __('Folder', 'wpmudev-plugin-test');
        } else if (mimeType.startsWith('image/')) {
            return __('Image', 'wpmudev-plugin-test');
        } else if (mimeType.startsWith('video/')) {
            return __('Video', 'wpmudev-plugin-test');
        } else if (mimeType.startsWith('audio/')) {
            return __('Audio', 'wpmudev-plugin-test');
        } else if (mimeType.includes('pdf')) {
            return __('PDF', 'wpmudev-plugin-test');
        } else if (mimeType.includes('document') || mimeType.includes('word')) {
            return __('Document', 'wpmudev-plugin-test');
        } else if (mimeType.includes('spreadsheet') || mimeType.includes('excel')) {
            return __('Spreadsheet', 'wpmudev-plugin-test');
        } else if (mimeType.includes('presentation') || mimeType.includes('powerpoint')) {
            return __('Presentation', 'wpmudev-plugin-test');
        } else {
            return __('File', 'wpmudev-plugin-test');
        }
    };

    // Loading state during initial auth check
    if (authStatusLoading) {
        return (
            <div className="sui-wrap">
                <div className="sui-header">
                    <h1 className="sui-header-title">
                        {__('Google Drive Test', 'wpmudev-plugin-test')}
                    </h1>
                    <p className="sui-description">
                        {__('Test Google Drive API integration for applicant assessment', 'wpmudev-plugin-test')}
                    </p>
                </div>
                <div className="sui-box">
                    <div className="sui-box-body">
                        <div className="drive-loading">
                            <Spinner />
                            <p>{__('Checking authentication status...', 'wpmudev-plugin-test')}</p>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="sui-wrap">
            <div className="sui-header">
                <h1 className="sui-header-title">
                    {__('Google Drive Test', 'wpmudev-plugin-test')}
                </h1>
                <p className="sui-description">
                    {__('Test Google Drive API integration for applicant assessment', 'wpmudev-plugin-test')}
                </p>
            </div>

            {notice.message && (
                <Notice status={notice.type} isDismissible onRemove={() => setNotice({ message: '', type: '' })}>
                    {notice.message}
                </Notice>
            )}

            {/* Credentials Setup */}
            {showCredentials ? (
                <div className="sui-box">
                    <div className="sui-box-header">
                        <h2 className="sui-box-title">
                            {__('Set Google Drive Credentials', 'wpmudev-plugin-test')}
                        </h2>
                    </div>
                    <div className="sui-box-body">
                        <div className="sui-box-settings-row">
                            <TextControl
                                help={createInterpolateElement(
                                    __('You can get Client ID from <a>Google Cloud Console</a>. Make sure to enable Google Drive API.', 'wpmudev-plugin-test'),
                                    {
                                        a: <a href="https://console.cloud.google.com/apis/credentials" target="_blank" rel="noopener noreferrer" />,
                                    }
                                )}
                                label={__('Client ID', 'wpmudev-plugin-test')}
                                value={credentials.clientId}
                                onChange={(value) => setCredentials({...credentials, clientId: value})}
                                placeholder={__('Enter your Google Client ID', 'wpmudev-plugin-test')}
                            />
                        </div>

                        <div className="sui-box-settings-row">
                            <TextControl
                                help={createInterpolateElement(
                                    __('You can get Client Secret from <a>Google Cloud Console</a>.', 'wpmudev-plugin-test'),
                                    {
                                        a: <a href="https://console.cloud.google.com/apis/credentials" target="_blank" rel="noopener noreferrer" />,
                                    }
                                )}
                                label={__('Client Secret', 'wpmudev-plugin-test')}
                                value={credentials.clientSecret}
                                onChange={(value) => setCredentials({...credentials, clientSecret: value})}
                                type="password"
                                placeholder={__('Enter your Google Client Secret', 'wpmudev-plugin-test')}
                            />
                        </div>

                        <div className="sui-box-settings-row">
                            <div className="sui-notice sui-notice-info">
                                <div className="sui-notice-content">
                                    <div className="sui-notice-message">
                                        <span className="sui-notice-icon sui-icon-info" aria-hidden="true"></span>
                                        <p>
                                            {__('Please use this URL in your Google API\'s Authorized redirect URIs field:', 'wpmudev-plugin-test')}
                                        </p>
                                        <p>
                                            <code style={{wordBreak: 'break-all', fontSize: '12px', display: 'block', padding: '8px', backgroundColor: '#f8f9fa', border: '1px solid #ddd'}}>
                                                {window.wpmudevDriveTest.redirectUri}
                                            </code>
                                        </p>
                                        <p>
                                            <small>
                                                {__('Copy this URL exactly as shown and add it to your Google Cloud Console project\'s OAuth 2.0 Client IDs configuration.', 'wpmudev-plugin-test')}
                                            </small>
                                        </p>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div className="sui-box-settings-row">
                            <p><strong>{__('Required scopes for Google Drive API:', 'wpmudev-plugin-test')}</strong></p>
                            <ul>
                                <li><code>https://www.googleapis.com/auth/drive.file</code></li>
                                <li><code>https://www.googleapis.com/auth/drive.readonly</code></li>
                            </ul>
                        </div>
                    </div>
                    <div className="sui-box-footer">
                        <div className="sui-actions-right">
                            <Button
                                variant="primary"
                                onClick={handleSaveCredentials}
                                disabled={isLoading || !credentials.clientId.trim() || !credentials.clientSecret.trim()}
                            >
                                {isLoading ? <Spinner /> : __('Save Credentials', 'wpmudev-plugin-test')}
                            </Button>
                        </div>
                    </div>
                </div>
            ) : !isAuthenticated ? (
                /* Authentication Section */
                <div className="sui-box">
                    <div className="sui-box-header">
                        <h2 className="sui-box-title">
                            {__('Authenticate with Google Drive', 'wpmudev-plugin-test')}
                        </h2>
                    </div>
                    <div className="sui-box-body">
                        <div className="sui-box-settings-row">
                            <p>{__('Please authenticate with Google Drive to proceed with the test.', 'wpmudev-plugin-test')}</p>
                            <p><strong>{__('This test will require the following permissions:', 'wpmudev-plugin-test')}</strong></p>
                            <ul>
                                <li>{__('View and manage Google Drive files', 'wpmudev-plugin-test')}</li>
                                <li>{__('Upload new files to Drive', 'wpmudev-plugin-test')}</li>
                                <li>{__('Create folders in Drive', 'wpmudev-plugin-test')}</li>
                            </ul>
                        </div>
                    </div>
                    <div className="sui-box-footer">
                        <div className="sui-actions-left">
                            <Button
                                variant="secondary"
                                onClick={() => setShowCredentials(true)}
                            >
                                {__('Change Credentials', 'wpmudev-plugin-test')}
                            </Button>
                        </div>
                        <div className="sui-actions-right">
                            <Button
                                variant="primary"
                                onClick={handleAuth}
                                disabled={isLoading}
                            >
                                {isLoading ? <Spinner /> : __('Authenticate with Google Drive', 'wpmudev-plugin-test')}
                            </Button>
                        </div>
                    </div>
                </div>
            ) : (
                /* Authenticated State - Main Interface */
                <>
                    {/* File Upload Section */}
                    <div className="sui-box">
                        <div className="sui-box-header">
                            <h2 className="sui-box-title">
                                {__('Upload File to Drive', 'wpmudev-plugin-test')}
                            </h2>
                        </div>
                        <div className="sui-box-body">
                            <div className="sui-box-settings-row">
                                <label className="sui-label">
                                    {__('Select File', 'wpmudev-plugin-test')}
                                </label>
                                <input
                                    type="file"
                                    onChange={(e) => setUploadFile(e.target.files[0])}
                                    className="drive-file-input"
                                    accept="*/*"
                                />
                                {uploadFile && (
                                    <div className="sui-description">
                                        <strong>{__('Selected:', 'wpmudev-plugin-test')}</strong> {uploadFile.name} ({formatFileSize(uploadFile.size)})
                                    </div>
                                )}
                            </div>
                            
                            {uploadProgress && (
                                <div className="sui-box-settings-row">
                                    <div className="upload-progress">
                                        <p><strong>{__('Upload Progress:', 'wpmudev-plugin-test')}</strong></p>
                                        <ProgressBar value={uploadProgress.progress} />
                                        <p className={uploadProgress.error ? 'error' : 'success'}>
                                            {uploadProgress.message}
                                        </p>
                                        {uploadProgress.stages && (
                                            <details>
                                                <summary>{__('View Details', 'wpmudev-plugin-test')}</summary>
                                                <ul>
                                                    {uploadProgress.stages.map((stage, index) => (
                                                        <li key={index}>
                                                            <strong>{stage.stage}:</strong> {stage.message} ({stage.progress}%)
                                                        </li>
                                                    ))}
                                                </ul>
                                            </details>
                                        )}
                                    </div>
                                </div>
                            )}
                        </div>
                        <div className="sui-box-footer">
                            <div className="sui-actions-right">
                                <Button
                                    variant="primary"
                                    onClick={handleUpload}
                                    disabled={isLoading || !uploadFile}
                                >
                                    {isLoading ? <Spinner /> : __('Upload to Drive', 'wpmudev-plugin-test')}
                                </Button>
                            </div>
                        </div>
                    </div>

                    {/* Create Folder Section */}
                    <div className="sui-box">
                        <div className="sui-box-header">
                            <h2 className="sui-box-title">
                                {__('Create New Folder', 'wpmudev-plugin-test')}
                            </h2>
                        </div>
                        <div className="sui-box-body">
                            <div className="sui-box-settings-row">
                                <TextControl
                                    label={__('Folder Name', 'wpmudev-plugin-test')}
                                    value={folderName}
                                    onChange={setFolderName}
                                    placeholder={__('Enter folder name', 'wpmudev-plugin-test')}
                                />
                            </div>
                        </div>
                        <div className="sui-box-footer">
                            <div className="sui-actions-right">
                                <Button
                                    variant="secondary"
                                    onClick={handleCreateFolder}
                                    disabled={isLoading || !folderName.trim()}
                                >
                                    {isLoading ? <Spinner /> : __('Create Folder', 'wpmudev-plugin-test')}
                                </Button>
                            </div>
                        </div>
                    </div>

                    {/* Files List Section */}
                    <div className="sui-box">
                        <div className="sui-box-header">
                            <h2 className="sui-box-title">
                                {__('Your Drive Files', 'wpmudev-plugin-test')}
                            </h2>
                            <div className="sui-actions-right">
                                <Button
                                    variant="secondary"
                                    onClick={loadFiles}
                                    disabled={isLoading}
                                    size="small"
                                >
                                    {isLoading ? <Spinner /> : __('Refresh Files', 'wpmudev-plugin-test')}
                                </Button>
                            </div>
                        </div>
                        <div className="sui-box-body">
                            {isLoading ? (
                                <div className="drive-loading">
                                    <Spinner />
                                    <p>{__('Loading files...', 'wpmudev-plugin-test')}</p>
                                </div>
                            ) : files.length > 0 ? (
                                <div className="drive-files-grid">
                                    {files.map((file) => (
                                        <div key={file.id} className={`drive-file-item ${file.isFolder ? 'is-folder' : 'is-file'}`}>
                                            <div className="file-info">
                                                <div className="file-name">
                                                    <strong>{file.name}</strong>
                                                    <span className="file-type">{getFileType(file.mimeType)}</span>
                                                </div>
                                                <div className="file-meta">
                                                    {file.size && (
                                                        <span className="file-size">{formatFileSize(file.size)}</span>
                                                    )}
                                                    <span className="file-date">
                                                        {file.modifiedTime 
                                                            ? new Date(file.modifiedTime).toLocaleDateString()
                                                            : __('Unknown date', 'wpmudev-plugin-test')
                                                        }
                                                    </span>
                                                </div>
                                            </div>
                                            <div className="file-actions">
                                                {file.webViewLink && (
                                                    <Button
                                                        variant="link"
                                                        size="small"
                                                        href={file.webViewLink}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                    >
                                                        {__('View in Drive', 'wpmudev-plugin-test')}
                                                    </Button>
                                                )}
                                                {!file.isFolder && (
                                                    <Button
                                                        variant="secondary"
                                                        size="small"
                                                        onClick={() => handleDownload(file.id, file.name)}
                                                    >
                                                        {__('Download', 'wpmudev-plugin-test')}
                                                    </Button>
                                                )}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <div className="sui-box-settings-row">
                                    <div className="sui-notice">
                                        <div className="sui-notice-content">
                                            <div className="sui-notice-message">
                                                <span className="sui-notice-icon sui-icon-info" aria-hidden="true"></span>
                                                <p>{__('No files found in your Drive. Upload a file or create a folder to get started.', 'wpmudev-plugin-test')}</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>

                    {hasMoreFiles && (
                        <div className="sui-box-footer">
                            <div className="sui-actions-center">
                                <Button
                                    variant="secondary"
                                    onClick={loadMoreFiles}
                                    disabled={isLoading}
                                >
                                    {isLoading ? <Spinner /> : __('Load More Files', 'wpmudev-plugin-test')}
                                </Button>
                            </div>
                        </div>
                    )}
                </>
            )}
        </div>
    );
}

if ( createRoot ) {
    createRoot( domElement ).render(<StrictMode><WPMUDEV_DriveTest/></StrictMode>);
} else {
    render( <StrictMode><WPMUDEV_DriveTest/></StrictMode>, domElement );
}