var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var mongoose = require('mongoose')
var session = require('express-session')
var passport = require('passport')
var compression = require('compression')
var fileUpload = require('express-fileupload')

var app = express()

var appRoutes = require('./routes/app')
var authRoutes = require('./routes/auth')
var apiRoutes = require('./routes/api')
var mongoConfig = require('./config/db')

mongoose.connect(mongoConfig.url)

require('./config/passport')(passport)

app.use(compression())
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))
app.use(fileUpload())
app.use(session({
    secret: 'mSmdumRCmCnT7rS',
    resave: true,
    saveUninitialized: true
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
    next()
})

app.use('/auth', authRoutes())
app.use('/app', appRoutes())
app.use('/api', apiRoutes())

app.get('/', function (req, res) {
    res.render('index')
})

app.listen(3000)

module.exports = app
