const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
require("dotenv").config();
const { MongoClient } = require("mongodb");
const mongoConfig = require("../config/mongo.config");
const Library = require("../models/Library"); // Conexión a MySQL
const { USE_MONGO } = require("../controllers/books"); // Cargar configuración de la base de datos

// Clave secreta para JWT
const SECRET_KEY = process.env.JWT_SECRET || "1234";

// Conectar a MongoDB si se usa
let dbClient = null;
if (USE_MONGO) {
    dbClient = new MongoClient(mongoConfig.MONGO_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    });
}

// **REGISTRO DE USUARIO (MYSQL/MONGODB)**
const registerUser = async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Faltan datos requeridos" });
    }

    try {
        let db;
        if (USE_MONGO) {
            if (!dbClient.topology || !dbClient.topology.isConnected()) {
                await dbClient.connect();
            }
            db = dbClient.db("library_db").collection("users");

            // Verificar si el usuario ya existe en MongoDB
            const existingUser = await db.findOne({ username });
            if (existingUser) {
                return res.status(400).json({ error: "El usuario ya existe" });
            }

            // Cifrar la contraseña y guardar en MongoDB
            const hashedPassword = await bcrypt.hash(password, 10);
            await db.insertOne({ username, password: hashedPassword });

        } else {
            db = new Library();
            const [existingUser] = await db.connection.query("SELECT * FROM users WHERE username = ?", [username]);
            if (existingUser.length > 0) {
                return res.status(400).json({ error: "El usuario ya existe" });
            }

            // Cifrar la contraseña y guardar en MySQL
            const hashedPassword = await bcrypt.hash(password, 10);
            await db.connection.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword]);
        }

        // Generar token JWT
        const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });
        res.status(201).json({ message: "Usuario registrado con éxito", token });

    } catch (error) {
        console.error("Error en el registro:", error);
        res.status(500).json({ error: "Error en el servidor" });
    }
};

// **INICIO DE SESIÓN (MYSQL/MONGODB)**
const generateToken = async (username, password) => {
    try {
        let db;
        let user;
        
        if (USE_MONGO) {
            if (!dbClient.topology || !dbClient.topology.isConnected()) {
                await dbClient.connect();
            }
            db = dbClient.db("library_db").collection("users");
            user = await db.findOne({ username });

        } else {
            db = new Library();
            const [users] = await db.connection.query("SELECT * FROM users WHERE username = ?", [username]);
            user = users[0]; // Primer resultado
        }

        if (!user) {
            return { error: "Usuario no encontrado" };
        }

        // Verificar contraseña
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return { error: "Contraseña incorrecta" };
        }

        // Generar token JWT
        const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: "1h" });
        return { token };

    } catch (error) {
        console.error("Error en autenticación:", error);
        return { error: "Error interno del servidor" };
    }
};

// **MIDDLEWARE DE AUTENTICACIÓN JWT**
const jwtAuth = (req, res, next) => {
    const token = req.header("Authorization");

    if (!token) {
        return res.status(401).json({ error: "Acceso denegado. Token requerido." });
    }

    try {
        const decoded = jwt.verify(token.replace("Bearer ", ""), SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: "Token inválido o expirado." });
    }
};

module.exports = { registerUser, generateToken, jwtAuth };
