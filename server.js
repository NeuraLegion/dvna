var express = require('express')
var session = require('express-session')

var app = express()

app.set('trust proxy', 1)

var sessionCookie = {
    httpOnly: true,
    sameSite: 'lax',
    secure: true
}

app.use(session({
    secret: process.env.SESSION_SECRET || 'change-me',
    resave: false,
    saveUninitialized: false,
    cookie: sessionCookie
}))

module.exports = app
