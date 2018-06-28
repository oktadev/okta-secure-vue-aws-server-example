const express = require('express')
const cors = require('cors')
const bodyParser = require('body-parser')
const OktaJwtVerifier = require('@okta/jwt-verifier')

const oktaJwtVerifier = new OktaJwtVerifier({
  clientId: '{clientId}',
  issuer: 'https://{devUrl}.oktapreview.com/oauth2/default'
})

let app = express()
app.use(cors())
app.use(bodyParser.json())

// verify JWT token middleware
const authRequired = () => {
  return (req, res, next) => {
    // require request to have an authorization header
    if (!req.headers.authorization) {
      return next(new Error('Authorization header is required'))
    }
    let parts = req.headers.authorization.trim().split(' ')
    let accessToken = parts.pop()
    oktaJwtVerifier.verifyAccessToken(accessToken)
      .then(jwt => {
        req.user = {
          uid: jwt.claims.uid,
          email: jwt.claims.sub
        }
        next()
      })
      .catch(next) // jwt did not verify!
  }
}

// public route that anyone can access
app.get('/hello', (req, res) => {
  return res.json({
    message: 'Hello world!'
  })
})

// route uses authRequired middleware to secure it
app.get('/secure-data', authRequired(), (req, res) => {
  return res.json({
    secret: 'The answer is aways "A"!'
  })
})

module.exports = app