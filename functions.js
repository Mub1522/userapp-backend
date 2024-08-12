const bcrypt = require('bcrypt');
const fs = require('fs').promises;
const path = require('path');
const htmlTemplateRecoveryPath = path.join(__dirname, './layouts/recovery.html');

/* Encriptar contraseñas */
async function hashPassword(password) {
    try {
        const saltRounds = 10;
        const hash = await bcrypt.hash(password, saltRounds);
        return hash;
    } catch (err) {
        console.error('Error al hashear la contraseña:', err);
    }
}

/* Recuperar plantilla de recuperacion de contraseñas */
async function getRecoveryEmailHtml(userEmail, userPassword) {
    try {
        let emailHtml = await fs.readFile(htmlTemplateRecoveryPath, 'utf8');

        emailHtml = emailHtml
            .replace('{{email}}', userEmail)
            .replace('{{password}}', userPassword);

        return emailHtml;
    } catch (error) {
        console.error('Error al leer o procesar el archivo HTML:', error);
        throw error;
    }
}

/* Función para enviar el correo electrónico */
async function sendRecoveryEmail(transport, userEmail, userPassword) {
    try {
        const emailHtml = await getRecoveryEmailHtml(userEmail, userPassword);

        const mailOptions = {
            from: process.env.EMAIL,
            to: userEmail,
            subject: 'Recuperación de Contraseña',
            html: emailHtml
        };

        const info = await transport.sendMail(mailOptions);
        console.log('Correo enviado correctamente:', info.response);
    } catch (error) {
        console.error('Error al enviar el correo:', error);
    }
}

module.exports = {
    hashPassword,
    sendRecoveryEmail
};
