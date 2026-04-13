var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var session = require('express-session')
var flash = require('connect-flash')
var csrf = require('csurf')
var helmet = require('helmet')

var indexRouter = require('./routes/index')
var appRouter = require('./routes/app')
var authRouter = require('./routes/auth')

var app = express()

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))
app.use(session({
    secret: process.env.SESSION_SECRET || 'change-me-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production'
    }
}))
app.use(flash())
app.use(csrf({ cookie: false }))

// Ensure the header is set globally on every response, including rendered pages,
// redirects, and any route-specific handlers.
app.use(function (req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff')
    next()
})

// Preserve the existing security baseline while explicitly keeping nosniff.
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
    crossOriginResourcePolicy: false,
    dnsPrefetchControl: false,
    frameguard: {
        action: 'sameorigin'
    },
    noSniff: false,
    xssFilter: false
}))

app.use('/', indexRouter)
app.use('/app', appRouter)
app.use('/auth', authRouter)

app.use(function (req, res, next) {
    res.status(404)
    res.render('error', {
        message: 'Not Found',
        error: {}
    })
})

module.exports = app
