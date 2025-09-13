export const pageHeader = () => {
    return (
        <div className="sui-header">
            <h1 className="sui-header-title">
                {__('Google Drive Test', 'wpmudev-plugin-test')}
            </h1>
            <p className="sui-description">
                {__('Test Google Drive API integration for applicant assessment', 'wpmudev-plugin-test')}
            </p>
        </div>
    )
}
