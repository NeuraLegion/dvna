var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')

var indexRouter = require('./routes/index')
var appRouter = require('./routes/app')
var authRouter = require('./routes/auth')
var homeRouter = require('./routes/home')
var apiRouter = require('./routes/api')
var adminRouter = require('./routes/admin')

var app = express()

app.set('trust proxy', 1)

app.use(function (req, res, next) {
    if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }

    next()
})

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
    secret: process.env.SESSION_SECRET || 'development-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: false
    }
}))

app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.use('/', indexRouter)
app.use('/auth', authRouter)
app.use('/home', homeRouter)
app.use('/api', apiRouter)
app.use('/admin', adminRouter)
app.use('/app', appRouter(app))

app.use(function (req, res, next) {
    res.status(404)
    res.render('error')
})

module.exports = app
