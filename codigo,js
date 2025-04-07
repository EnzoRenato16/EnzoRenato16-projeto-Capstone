require('dotenv').config();
const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Configurações
const app = express();
app.use(express.json());
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'segredo';
const sequelize = new Sequelize(
  process.env.DB_NAME || 'safevault',
  process.env.DB_USER || 'root',
  process.env.DB_PASS || '',
  {
    host: 'localhost',
    dialect: 'mysql',
    logging: false,
  }
);

// Modelo
const User = sequelize.define('User', {
  username: { type: DataTypes.STRING, allowNull: false, unique: true },
  password: { type: DataTypes.STRING, allowNull: false },
  role: { type: DataTypes.STRING, defaultValue: 'user' },
});

// Middleware de autenticação
function authMiddleware(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ message: 'Token ausente' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(403).json({ message: 'Token inválido' });
  }
}

// Middleware de autorização por função
function roleMiddleware(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Acesso negado' });
    }
    next();
  };
}

// Rotas
app.post('/register', [
  check('username').isAlphanumeric().withMessage('Nome de usuário inválido'),
  check('password').isLength({ min: 6 }).withMessage('Senha deve ter pelo menos 6 caracteres'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, password, role } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  try {
    const user = await User.create({ username, password: hashed, role });
    res.status(201).json({ message: 'Usuário registrado com sucesso' });
  } catch (err) {
    res.status(400).json({ error: 'Nome de usuário já em uso' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ where: { username } });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }

  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

app.get('/admin', authMiddleware, roleMiddleware('admin'), (req, res) => {
  res.json({ message: `Bem-vindo, administrador ${req.user.id}` });
});

app.get('/user', authMiddleware, (req, res) => {
  res.json({ message: `Bem-vindo, usuário ${req.user.id}` });
});

// Inicialização
sequelize.sync().then(() => {
  app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
  });
});
