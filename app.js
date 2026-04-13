var express = require('express')
var serverConfig = require('./config/server')
var app = express()

app.use(function (req, res, next) {
    var requestOrigin = req.headers.origin
    var allowedOrigin = serverConfig.corsOrigin

    if (allowedOrigin) {
        res.setHeader('Vary', 'Origin')

        if (requestOrigin && requestOrigin === allowedOrigin) {
            res.setHeader('Access-Control-Allow-Origin', requestOrigin)
        } else if (!requestOrigin) {
            res.setHeader('Access-Control-Allow-Origin', allowedOrigin)
        }

        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    }

    if (req.method === 'OPTIONS') {
        return res.sendStatus(204)
    }

    next()
})

module.exports = app
