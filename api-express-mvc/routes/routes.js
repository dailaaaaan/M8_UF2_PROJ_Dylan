const express = require("express");
const { registerUser, generateToken, jwtAuth } = require("../middleware/auth");
const books = require("../controllers/books");

const router = express.Router();

// Rutas CRUD de libros
router.get("/api/books", books.getBooks);
router.post("/api/books", books.createBook);
router.put("/api/books", books.updateBook);
router.delete("/api/books", books.deleteBook);

// Rutas de autenticación
router.post("/api/login", async (req, res) => {
    const { username, password } = req.body;
    const result = await generateToken(username, password);
    if (result.error) {
        return res.status(401).json({ error: result.error });
    }
    res.json(result);
});

router.post("/api/register", registerUser);

module.exports = router;
