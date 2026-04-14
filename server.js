var express = require('express')
var session = require('express-session')

var app = express()

app.set('trust proxy', 1)

app.use(session({
    secret: 'dvanonsecret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'lax'
    }
}))

module.exports = app
