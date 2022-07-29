const express = require('express')
const app = express()
const port = 8080
const jwt = require('jsonwebtoken')
const ethers = require('ethers')

const jwtSecret = 'SECRET-WORD' // never reveal this

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*')
  res.header(
    'Access-Control-Allow-Headers',
    'Authorization,X-API-KEY, Origin, X-Requested-With, Content-Type,Access-Control-Allow-Request-Method',
  )
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTION, PUT, DELETE')
  res.header('Allow', 'GET, POST, OPTIONS, PUT, DELETE')
  next()
})

app.get('/', (req, res) => {
  res.status(200).send('Backend web3 auth')
})

app.get('/nonce', (req, res) => {
  const nonce = new Date().getTime()
  const address = req.query.address

  const tempToken = jwt.sign({ nonce, address }, jwtSecret, {
    expiresIn: '120s',
  })
  const message = getSignMessage(address, nonce)
  res.json({ tempToken, message })
})

app.post('/verify', async (req, res) => {
  const authHeader = req.headers['authorization']
  const tempToken = authHeader && authHeader.split(' ')[1]
  if (tempToken === undefined)
    return res.status(403).send({ msg: 'Missing authorization header' })
  const userData = await jwt.verify(tempToken, jwtSecret)
  const nonce = userData.nonce
  const address = userData.address
  const message = getSignMessage(address, nonce)
  const signature = req.query.signature
  const signerAddress = await ethers.utils.verifyMessage(message, signature)
  if (signerAddress.toLocaleLowerCase() === address.toLocaleLowerCase()) {
    const token = jwt.sign({ signerAddress }, jwtSecret, { expiresIn: '1d' })
    return res.json({ token: token, msg: 'User verifed' })
  }
})

app.get('/secret', authenticateTokenMiddleware, async (req, res) => {
  return res.json({ msg: 'This is a secret message for authenticated users' })
})

function authenticateTokenMiddleware(req, res, next) {
  const authHeader = req.headers['authorization']
  const tempToken = authHeader && authHeader.split(' ')[1]
  if (tempToken === undefined)
    return res.status(401).send({ msg: 'No authorized' })

  jwt.verify(tempToken, jwtSecret, (err, authData) => {
    if (err) return res.status(403).send({ msg: 'No authorized' })
    req.authData = authData
    next()
  })
}

const getSignMessage = (address, nonce) => {
  return `Please sign this message for address ${address}:\n\n${nonce}`
}

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
