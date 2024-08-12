const express = require('express');
let cors = require('cors');
const connection = require('./connection');
const userRoute = require('./routes/userRoute');
const app = express();


app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use('/userRoute', userRoute);

module.exports = app;