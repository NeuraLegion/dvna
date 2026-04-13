var express = require('express')
var app = express()
var serverConfig = require('./config/server')

app.use(function (req, res, next) {
    if (serverConfig.corsOrigin) {
        res.setHeader('Access-Control-Allow-Origin', serverConfig.corsOrigin)
        res.setHeader('Vary', 'Origin')
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    }

    if (req.method === 'OPTIONS') {
        return res.sendStatus(204)
    }

    next()
})

module.exports = app
