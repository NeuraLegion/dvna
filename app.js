var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')
var createError = require('http-errors')
var helmet = require('helmet')
var isHttpsRequest = require('./core/isHttpsRequest')

var indexRouter = require('./routes/index')
var appRouter = require('./routes/app')
var authRouter = require('./routes/auth')
var adminRouter = require('./routes/admin')

var app = express()

app.set('trust proxy', 1)

app.use(function (req, res, next) {
    if (isHttpsRequest(req)) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }

    next()
})

app.use(helmet({
    contentSecurityPolicy: false
}))

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
    secret: process.env.SESSION_SECRET || 'change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: isHttpsRequest({
            secure: true,
            headers: {}
        })
    }
}))

app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use('/', indexRouter)
app.use('/', authRouter)
app.use('/', adminRouter)
app.use('/', appRouter(app))

app.use(function (req, res, next) {
    next(createError(404))
})

app.use(function (err, req, res, next) {
    res.locals.message = err.message
    res.locals.error = req.app.get('env') === 'development' ? err : {}

    res.status(err.status || 500)
    res.render('error')
})

module.exports = app
