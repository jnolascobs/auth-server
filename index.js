const express = require('express');
const cors = require('cors');
const { dbConnection } = require('./db/config');
require('dotenv').config()

// console.log(process.env);

// Crear el servidor/aplicación de express
const app = express();

// Base de datos
dbConnection();

// Directorio Público
app.use(express.static('public'))

// CORS
app.use(cors());

// Lectura y parse del body
app.use(express.json());

// Rutas
app.use('/api/auth', require('./routes/auth'));

app.listen(process.env.PORT, () => {
    console.log(`Server running on port ${process.env.PORT}`);
})

