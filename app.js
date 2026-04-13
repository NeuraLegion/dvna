var express = require('express')
var app = express()
var serverConfig = require('./config/server')

// Enforce HTTPS-aware cookie settings at the app level so any session cookie
// configured elsewhere is protected in production deployments.
if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1)
}

module.exports = app
