var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var session = require('express-session')
var flash = require('connect-flash')
var helmet = require('helmet')

var app = express()

app.set('trust proxy', 1)

// Apply clickjacking protection globally so every response path inherits it.
app.use(helmet({
    frameguard: { action: 'sameorigin' },
    contentSecurityPolicy: {
        useDefaults: true,
        directives: {
            frameAncestors: ["'self'"]
        }
    }
}))

app.use(function (req, res, next) {
    if (!res.getHeader('X-Frame-Options')) {
        res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    }
    if (!res.getHeader('Content-Security-Policy')) {
        res.setHeader('Content-Security-Policy', "frame-ancestors 'self'")
    }
    next()
})

app.use(express.static(path.join(__dirname, 'public')))
app.use(cookieParser())
app.use(session({
    secret: process.env.SESSION_SECRET || 'change-this-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: app.get('env') === 'production'
    }
}))
app.use(flash())

module.exports = app
