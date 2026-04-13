var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var session = require('express-session')
var passport = require('passport')
var bodyParser = require('body-parser')
var helmet = require('helmet')

var app = express()

// If the app is deployed behind a reverse proxy / load balancer, honor X-Forwarded-* headers
// so req.secure works correctly for HTTPS requests.
app.set('trust proxy', true)

app.use(helmet())
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
    secret: process.env.SESSION_SECRET || 'keyboard cat',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: 'auto'
    }
}))

app.use(passport.initialize())
app.use(passport.session())

app.use('/app', require('./routes/app')())
app.use('/', require('./routes/public')())

module.exports = app
