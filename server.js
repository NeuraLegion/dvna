var express = require('express')
var app = express()
var session = require('express-session')

// Enable trust proxy support when the app is deployed behind a reverse proxy
app.set('trust proxy', 1)

app.use(session({
    secret: 'keyboard cat',
    resave: true,
    saveUninitialized: true,
    cookie: {
        secure: true,
        httpOnly: true,
        sameSite: 'lax'
    }
}))

module.exports = app
