const { response } = require('express');
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const { generateJWT } = require('../helpers/jwt');

const createUser = async (req, res = response) => {

    const {name, email, password} = req.body;

    try {
        // Verificar el email
        const user = await User.findOne({email});

        if (user) {
            return res.status(400).json({
                ok: false,
                msg: 'Ya existe un usuario con ese email'
            })
        }

        // Crear usuario con el modelo
        const dbUser = new User(req.body);

        // Hash password
        const salt = bcrypt.genSaltSync();
        dbUser.password = bcrypt.hashSync(password, salt);

        // Generar JWT
        const token = await generateJWT(dbUser.id, name);

        // Crear usuario de la BD
        await dbUser.save();

        // Generar respuesta exitosa
        return res.status(201).json({
            ok: true,
            uid: dbUser.id,
            name,
            token
        })

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            ok: false,
            msg: 'Error al registrar usuario'
        })
    }
}

const loginUser = async (req, res = response) => {

    const {email, password} = req.body;

    try {
        const dbUser = await User.findOne({email})

        if (!dbUser) {
            return res.status(400).json({
                ok: false,
                msg: 'No existe ningún usuario registrado con ese correo'
            })
        }

        // Confirmar si la contraseña coincide
        const validPassword = bcrypt.compareSync(password, dbUser.password)

        if (!validPassword) {
            return res.status(400).json({
                ok: false,
                msg: 'Contraseña incorrecta'
            })
        }

        // Generar JWT
        const token = await generateJWT(dbUser.id, dbUser.name);

        // Respuesta del servicio
        return res.json({
            ok: true,
            uid: dbUser.id,
            name: dbUser.name,
            token
        })

    } catch (error) {
        console.log(error);
        return res.json({
            ok: false,
            msg: 'Error al iniciar sesión'
        })
    }
}

const renewToken = async (req, res) => {

    const {uid, name} = req;

    // Generar JWT
    const token = await generateJWT(uid, name);

    return res.json({
        ok: true,
        uid,
        name,
        token
    })
}

module.exports = {createUser, loginUser, renewToken}

