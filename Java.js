const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

// 🔐 CLAVE SEGURA (mejor usar .env)
const JWT_SECRET = "spacecode_super_secret_key";

// DB
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "spacecode"
});

// ======================
// 🔥 REGISTRO
// ======================
app.post("/register", async (req, res) => {

try {

const { nombre, email, password } = req.body;

// validación básica
if (!nombre || !email || !password) {
return res.status(400).json({ error: "Campos incompletos" });
}

const hash = await bcrypt.hash(password, 10);

db.query(
"INSERT INTO usuarios (nombre,email,password) VALUES (?,?,?)",
[nombre, email, hash],
(err) => {

if (err) {
return res.status(500).json({ error: "Error al registrar usuario" });
}

res.json({ message: "Usuario creado correctamente 🚀" });

}
);

} catch (error) {
res.status(500).json({ error: "Error del servidor" });
}

});

// ======================
// 🔐 LOGIN
// ======================
app.post("/login", (req, res) => {

const { email, password } = req.body;

if (!email || !password) {
return res.status(400).json({ error: "Campos incompletos" });
}

db.query(
"SELECT * FROM usuarios WHERE email=?",
[email],
async (err, result) => {

if (err) {
return res.status(500).json({ error: "Error del servidor" });
}

if (result.length === 0) {
return res.status(404).json({ error: "Usuario no existe" });
}

const user = result[0];

try {

const valid = await bcrypt.compare(password, user.password);

if (!valid) {
return res.status(401).json({ error: "Contraseña incorrecta" });
}

// 🔐 TOKEN CON EXPIRACIÓN
const token = jwt.sign(
{
id: user.id,
nombre: user.nombre
},
JWT_SECRET,
{ expiresIn: "2h" }
);

res.json({ token });

} catch (error) {
res.status(500).json({ error: "Error al validar contraseña" });
}

}
);

});

// ======================
// 🚀 SERVIDOR
// ======================
app.listen(3000, () => {
console.log("🚀 Servidor en puerto 3000");
});