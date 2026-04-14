var express = require('express')
var path = require('path')
var bodyParser = require('body-parser')
var cookieParser = require('cookie-parser')
var session = require('express-session')
var passport = require('passport')

var app = express()

app.set('trust proxy', 1)

app.use(cookieParser())
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(session({
    secret: process.env.SESSION_SECRET || 'change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true
    }
}))
app.use(passport.initialize())
app.use(passport.session())

app.use(express.static(path.join(__dirname, 'public')))

module.exports = app
