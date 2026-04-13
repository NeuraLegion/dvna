module.exports = {
    listen: process.env.APP_LISTEN || '0.0.0.0',
    port: process.env.APP_PORT || process.env.PORT || 9090,
    corsOrigin: process.env.CORS_ORIGIN || '',
    cookieSecure: process.env.COOKIE_SECURE === 'true'
}
