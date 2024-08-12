require('dotenv').config();
const express = require('express');
const connection = require('../connection');
const router = express.Router();
const { hashPassword, sendRecoveryEmail } = require('../functions');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');

/* Register */
router.post('/signup', async (req, res) => {
    try {
        let user = req.body;
        let query = 'SELECT * FROM users WHERE email = ?';

        connection.query(query, [user.email], async (err, results) => {
            if (!err) {
                if (results.length === 0) {
                    query = "INSERT INTO users(name, email, password, role) VALUES (?, ?, ?, 'user');";

                    let userPassword = await hashPassword(user.password);

                    connection.query(query, [user.name, user.email, userPassword], (err, results) => {
                        if (!err) {
                            if (results.affectedRows > 0) {
                                return res.status(200).json({ message: 'Usuario registrado correctamente.' });
                            } else {
                                return res.status(500).json({ message: 'Usuario no registrado correctamente.' });
                            }
                        } else {
                            return res.status(500).json(err);
                        }
                    });
                } else {
                    return res.status(400).json({ message: 'Ya hay un usuario con el email ingresado.' });
                }
            } else {
                return res.status(500).json(err);
            }
        });
    } catch (error) {
        return res.status(500).json({ message: 'Error en la base de datos.', err });
    }
});

/* Login */
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email y contraseña son obligatorios.' });
    }

    let query = 'SELECT * FROM users WHERE email = ?';
    connection.query(query, [email], async (err, results) => {
        if (!err) {
            if (results.length === 0) {
                return res.status(401).json({ message: 'Credenciales incorrectas.' });
            } else {
                const user = results[0];

                /* Verificar el hash de la contraseña */
                const validPassword = await bcrypt.compare(password, user.password);
                if (!validPassword) {
                    return res.status(401).json({ message: 'Credenciales incorrectas.' });
                }

                if (user.status === 0) {
                    return res.status(401).json({ message: 'Usuario inactivo.' });
                }

                const response = {
                    email: user.email,
                    role: user.role
                };

                try {
                    const accessToken = jwt.sign(response, process.env.ACCESS_TOKEN, {
                        expiresIn: "8h",
                    });
                    return res.status(200).json({ token: accessToken });
                } catch (tokenError) {
                    return res.status(500).json({ message: 'Error generando el token.' });
                }
            }
        } else {
            return res.status(500).json({ message: 'Error en la base de datos.', err });
        }
    });
});

const transport = nodemailer.createTransport({
    host: 'smtp.zoho.com',
    port: 587, // O usa 465 si usas SSL
    secure: false, // Usa true si estás en el puerto 465
    service: 'zohomail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD
    }
});

/* Recovery password */
router.post('/recovery', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'El email es obligatorio.' });
    }

    let query = 'SELECT * FROM users WHERE email = ?';
    connection.query(query, [email], async (err, results) => {
        if (!err) {
            if (results.length === 0) {
                return res.status(401).json({ message: 'Si el correo electrónico está registrado, recibirás un enlace para restablecer tu contraseña.' });
            } else {
                const user = results[0];
                await sendRecoveryEmail(transport, user.email, user.password);
                return res.status(200).json({ message: 'Si el correo electrónico está registrado, recibirás un enlace para restablecer tu contraseña.' });
            }
        }
        else {
            return res.status(500).json({ message: 'Error en la base de datos.', err });
        }
    });
});


module.exports = router;