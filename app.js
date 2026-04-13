var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var favicon = require('serve-favicon')
var session = require('express-session')
var MongoStore = require('connect-mongo')(session)
var flash = require('connect-flash')
var bodyParser = require('body-parser')
var csrf = require('csurf')
var appConfig = require('./config/app')
var serverConfig = require('./config/server')

var indexRouter = require('./routes/index')
var appRouter = require('./routes/app')
var authRouter = require('./routes/auth')
var adminRouter = require('./routes/admin')

var app = express()

// Enforce browser MIME-sniffing protection for every response, including
// rendered pages, static assets, redirects, and error responses.
app.use(function (req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff')
    next()
})

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))
app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))

app.use(session({
    secret: appConfig.sessionSecret,
    resave: false,
    saveUninitialized: false,
    store: new MongoStore({
        url: serverConfig.mongoUrl,
        collection: 'sessions'
    })
}))

app.use(flash())
app.use(csrf())

app.use(function (req, res, next) {
    res.locals.csrfToken = req.csrfToken()
    next()
})

app.use('/', indexRouter())
app.use('/app', appRouter())
app.use('/auth', authRouter())
app.use('/admin', adminRouter())

// Make sure error responses also include the security header.
app.use(function (err, req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff')
    next(err)
})

module.exports = app
