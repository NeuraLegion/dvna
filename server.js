var express = require('express')
var app = express()
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var routes = require('./routes')

app.set('trust proxy', 1)

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(session({
    secret: 'change-this-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true
    }
}))
app.use(passport.initialize())
app.use(passport.session())

app.use('/', routes)

module.exports = app
