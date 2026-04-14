var express = require('express')
var app = express()
var path = require('path')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var session = require('express-session')
var cookieParser = require('cookie-parser')
var passport = require('passport')
var config = require('./config/server')

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')
app.set('env', process.env.NODE_ENV || 'development')

app.use(cookieParser())
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(session(config.session))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use(function (err, req, res, next) {
    if (err) {
        console.error('Unhandled application error:', err && err.message ? err.message : err)
    }

    if (res.headersSent) {
        return next(err)
    }

    req.flash('danger', 'An unexpected error occurred')
    res.status(500).render('app/modifyproduct', {
        output: {
            product: {}
        }
    })
})

module.exports = app