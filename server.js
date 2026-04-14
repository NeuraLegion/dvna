var express = require('express')
var path = require('path')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var helmet = require('helmet')

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

app.use(helmet.hsts({
    maxAge: 15552000,
    includeSubDomains: true
}))

app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "https://maxcdn.bootstrapcdn.com", "https://cdnjs.cloudflare.com"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://maxcdn.bootstrapcdn.com"],
        imgSrc: ["'self'", "data:"],
        fontSrc: ["'self'", "data:", "https://maxcdn.bootstrapcdn.com"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'self'"]
    }
}))

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

module.exports = app
