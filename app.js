const express = require('express')
const path = require('path')
const logger = require('morgan')
const cookieParser = require('cookie-parser')
const bodyParser = require('body-parser')
const session = require('express-session')

const app = express()

// Trust the first proxy so req.secure reflects the original protocol when HTTPS is
// terminated at a load balancer / reverse proxy.
app.set('trust proxy', 1)

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())

// Enforce Secure cookies whenever the request is served over HTTPS.
// This avoids relying only on NODE_ENV, which can leave cookies unprotected
// in HTTPS deployments that are not marked as production.
app.use((req, res, next) => {
  const isSecureRequest = req.secure || req.headers['x-forwarded-proto'] === 'https'

  session({
    secret: process.env.SESSION_SECRET || 'change_this_session_secret',
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      secure: isSecureRequest,
      httpOnly: true,
      sameSite: 'lax'
    }
  })(req, res, next)
})

app.use(express.static(path.join(__dirname, 'public')))

module.exports = app
