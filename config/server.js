module.exports = {
    listen: process.env.APP_LISTEN || '0.0.0.0',
    port: process.env.APP_PORT || process.env.PORT || 9090,
    corsOrigin: process.env.CORS_ORIGIN || '',
    // Session cookies must only be sent over HTTPS.
    cookieSecure: process.env.NODE_ENV === 'production'
}
