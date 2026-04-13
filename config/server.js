module.exports = {
    listen: process.env.APP_LISTEN || '0.0.0.0',
    port: process.env.APP_PORT || process.env.PORT || 9090,
    // Comma-separated allowlist of trusted origins.
    // Example: "https://localhost:9090,https://app.example.com"
    corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:9090,http://127.0.0.1:9090',
    // Secure cookies should be used by default in production and when the app is behind HTTPS.
    // Set COOKIE_SECURE=false only for local development over plain HTTP.
    cookieSecure: process.env.NODE_ENV === 'production' || process.env.COOKIE_SECURE === 'true'
}
