var express = require('express')
var path = require('path')
var app = express()
var bodyParser = require('body-parser')
var cookieParser = require('cookie-parser')
var session = require('express-session')

var isProduction = process.env.NODE_ENV === 'production'

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())

app.use(function (req, res, next) {
    var isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https'

    res.cookie = (function (origCookie) {
        return function (name, value, options) {
            options = options || {}
            if (options.secure === undefined) {
                options.secure = isHttps || isProduction
            }
            return origCookie.call(this, name, value, options)
        }
    })(res.cookie)

    next()
})

app.use(session({
    secret: process.env.SESSION_SECRET || 'change-this-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: isProduction,
        httpOnly: true
    }
}))

app.use('/', require('./routes'))

module.exports = app
