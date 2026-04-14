module.exports = {
    listen: process.env.APP_LISTEN || '0.0.0.0',
    port: process.env.APP_PORT || process.env.PORT || 9090,
    session: {
        secret: process.env.SESSION_SECRET || 'dvanonsecret',
        resave: false,
        saveUninitialized: false,
        proxy: true,
        cookie: {
            httpOnly: true,
            secure: true,
            sameSite: 'lax',
            path: '/'
        }
    }
}
