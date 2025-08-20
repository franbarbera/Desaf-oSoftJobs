import express from "express";
import dotenv from "dotenv";
import morgan from "morgan";
import { Pool } from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(morgan("dev"));

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
});

const validarToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader)
    return res.status(401).json({ error: "Token no proporcionado" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.email = decoded.email;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Token inválido" });
  }
};

app.post("/usuarios", async (req, res) => {
  try {
    const { email, password, rol, lenguage } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Faltan credenciales" });

    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);

    const result = await pool.query(
      "INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING *",
      [email, hashedPassword, rol, lenguage]
    );

    res
      .status(201)
      .json({ mensaje: "Usuario registrado", usuario: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al registrar usuario" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Faltan credenciales" });

    const result = await pool.query("SELECT * FROM usuarios WHERE email = $1", [
      email,
    ]);
    const usuario = result.rows[0];
    if (!usuario)
      return res.status(404).json({ error: "Usuario no encontrado" });

    const passwordValida = bcrypt.compareSync(password, usuario.password);
    if (!passwordValida)
      return res.status(401).json({ error: "Contraseña incorrecta" });

    const token = jwt.sign({ email: usuario.email }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al iniciar sesión" });
  }
});

app.get("/usuarios", validarToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, email, rol, lenguage FROM usuarios WHERE email = $1",
      [req.email]
    );
    const usuario = result.rows[0];
    if (!usuario)
      return res.status(404).json({ error: "Usuario no encontrado" });

    res.json(usuario);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al obtener usuario" });
  }
});

app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});
