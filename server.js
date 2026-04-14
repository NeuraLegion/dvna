var express = require('express')
var path = require('path')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')

var index = require('./routes/index')
var app = require('./routes/app')
var auth = require('./routes/auth')
var post = require('./routes/post')
var profile = require('./routes/profile')
var score = require('./routes/score')
var redirects = require('./routes/redirects')
var challenges = require('./routes/challenges')
var public = require('./routes/public')
var utilities = require('./routes/utilities')

var app = express()

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

// Strong CSP applied to every response path.
// Kept in middleware rather than individual handlers so it also protects
// rendered pages such as /app/calc and any other route added later.
app.use(function (req, res, next) {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' data: https://maxcdn.bootstrapcdn.com; connect-src 'self'"
    )
    next()
})

// Retain explicit frame protection for browsers and proxies that honor it.
app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    next()
})

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))
app.use(express.static(path.join(__dirname, 'views')))
app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())

app.use('/', index())
app.use('/app', app())
app.use('/auth', auth())
app.use('/post', post())
app.use('/profile', profile())
app.use('/score', score())
app.use('/redirects', redirects())
app.use('/challenges', challenges())
app.use('/public', public())
app.use('/utilities', utilities())

// Fallback middleware to ensure the header is always present even if a route
// or earlier middleware changes headers unexpectedly.
app.use(function (req, res, next) {
    if (!res.getHeader('Content-Security-Policy')) {
        res.setHeader(
            'Content-Security-Policy',
            "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' data: https://maxcdn.bootstrapcdn.com; connect-src 'self'"
        )
    }
    next()
})

module.exports = app
