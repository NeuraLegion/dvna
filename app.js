var express = require('express')
var session = require('express-session')
var isHttpsRequest = require('./core/isHttpsRequest')

var app = express()

app.set('trust proxy', 1)

app.use(session({
    secret: process.env.SESSION_SECRET || 'change-me',
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: function (req) {
            if (process.env.NODE_ENV === 'production') {
                return isHttpsRequest(req)
            }

            return false
        }
    }
}))

module.exports = app
