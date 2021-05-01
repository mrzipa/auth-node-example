const { Router } = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const { check, validationResult } = require('express-validator')
const User = require('../models/User')
const router = Router()
const tokenList = {}

// api/auth/register
router.post(
  '/register',
  [
    check('email', 'bad email').isEmail(),
    check('password', 'Length of password must be 6 symbols').isLength({ min: 6 })
  ],
  async (req, res) => {
    console.log(req.body)
    try {
      const errors = validationResult(req)

      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: 'Bad data from registration'
        })
      }

      const { email, password } = req.body

      const candidate = await User.findOne({ email })
      if (candidate) {
        return res.status(400).json({ message: 'User is exist' })
      }

      const hashedPassword = await bcrypt.hash(password, 12)
      const user = new User({ email, password: hashedPassword })

      await user.save()

      res.status(201).json({ message: 'User was created' })


    } catch (e) {
      res.status(500).json({ message: 'Something went wrong' })
    }
  })

// api/auth/login
router.post(
  '/login',
  [
    check('email', 'Input correct email').normalizeEmail().isEmail(),
    check('password', 'Input password').exists()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: 'Bad data from login'
        })
      }

      const { email, password } = req.body
      const user = await User.findOne({ email })
      if (!user) {
        return res.status(400).json({ message: 'User was not found' })
      }
      const isMatch = await bcrypt.compare(password, user.password)
      if (!isMatch) {
        return res.status(400).json({ message: 'Incorrect password' })
      }

      const token = jwt.sign(
        { userId: user.id },
        config.get('jwtSecret'),
        { expiresIn: '1h' }
      )

      const refreshToken = jwt.sign(
        { userId: user.id },
        config.get('refreshTokenSecret'),
        { expiresIn: '24h' }
      )

      tokenList[refreshToken] = { token, refreshToken }

      res.status(200).json({ token, refreshToken, userId: user.id })

    } catch (e) {
      res.status(500).json({ message: 'Something went wrong' })
    }
  })

// api/auth/token
router.post('/token', async (req, res) => {
  const postData = req.body
  if ((postData.refreshToken) && (postData.refreshToken in tokenList)) {
    const user = await User.findOne({ email })
    const token = jwt.sign(
      { userId: user.id },
      config.get('jwtSecret'),
      { expiresIn: '1h' }
    )
    tokenList[postData.refreshToken].token = token
    res.status(200).json({ token })
  } else {
    res.status(400).send('Invalid request')
  }
})

//api/auth/token/reject
router.post('/token/reject', (req, res) => {
  console.log('token before: ', tokenList)
  const refreshToken = req.body.refreshToken
  console.log('refresh token: ', refreshToken)
  if (refreshToken in tokenList) {
    delete tokenList[refreshToken]
  }
  console.log('token after: ', tokenList)
  res.status(204).json({ message: 'token was deleted' })
})


module.exports = router