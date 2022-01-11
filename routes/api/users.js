const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');

// User Model
const User = require('../../models/User');

// @route        POST api/users
// @descriptions Register User route
// @access       Public
router.post('/', [
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Please enter a password with 8 or more characters').isLength({ min: 6 }),
    check('pin', 'Pin is required').not().isEmpty(),
], async (req, res) => {
    const errors = validationResult(req)
    if(!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { name, email, password, pin} = req.body;

    try {
        // See if user exists
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ errors: [{ msg: 'User already exists'}] });
        }

        // Get Users pin
        user = new User({
            name,
            email,
            pin,
            password
        });

        // Encrypt Password 
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        await user.save();

        // Return JsonWebToken
        const payload = {
            user: {
                id: user.id
            }
        }

        jwt.sign(payload,
        config.get('jwtSecret'),
        { expiresIn: 3600 },
        (err, token) => {
            if (err) throw err;
            res.json({ token });
        });


    } catch(err) {
        console.error(err.message);
        res.status(500).send('Internal Server Error');
    }

});

module.exports = router;