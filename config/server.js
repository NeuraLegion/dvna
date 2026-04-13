module.exports = {
    listen: process.env.APP_LISTEN || '0.0.0.0',
    port: process.env.APP_PORT || process.env.PORT || 9090,
    corsOrigin: process.env.CORS_ORIGIN || '',
    // Keep secure cookies enabled in production/HTTPS deployments.
    // Defaults to true in production; can also be forced via COOKIE_SECURE=true.
    cookieSecure: process.env.NODE_ENV === 'production' || process.env.COOKIE_SECURE === 'true'
}
