const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

// Configuración
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'tu-secreto-super-seguro-cambiar-en-produccion';

// Base de datos PostgreSQL
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Inicializar base de datos
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        nombre TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        telefono TEXT,
        rol TEXT DEFAULT 'viewer',
        temp_password BOOLEAN DEFAULT false,
        fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        activo BOOLEAN DEFAULT true
      );

      CREATE TABLE IF NOT EXISTS tramites_data (
        id SERIAL PRIMARY KEY,
        tramite_id INTEGER NOT NULL,
        requisito TEXT NOT NULL,
        estado_doc TEXT,
        vigencia TEXT,
        fecha_venc TEXT,
        costo_tramite DECIMAL DEFAULT 0,
        pago_tramite TEXT,
        costo_gestor DECIMAL DEFAULT 0,
        pago_gestor TEXT,
        avance DECIMAL DEFAULT 0,
        notas TEXT,
        actualizado_por INTEGER,
        fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(tramite_id, requisito)
      );

      CREATE TABLE IF NOT EXISTS proyecto_info (
        id INTEGER PRIMARY KEY DEFAULT 1,
        nombre TEXT,
        ubicacion TEXT,
        responsable TEXT,
        fecha_inicio TEXT,
        gestor_nombre TEXT,
        gestor_telefono TEXT,
        gestor_email TEXT,
        gestor_empresa TEXT
      );

      CREATE TABLE IF NOT EXISTS sesiones (
        id SERIAL PRIMARY KEY,
        usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
        token TEXT UNIQUE,
        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        fecha_expiracion TIMESTAMP
      );
    `);

    // Crear admin por defecto si no existe
    const adminCheck = await client.query('SELECT id FROM usuarios WHERE email = $1', ['admin@empresa.com']);
    if (adminCheck.rows.length === 0) {
      await client.query(
        'INSERT INTO usuarios (nombre, email, password, rol, temp_password) VALUES ($1, $2, $3, $4, $5)',
        ['Administrador', 'admin@empresa.com', '1234', 'admin', false]
      );
      console.log('✅ Usuario admin creado (admin@empresa.com / 1234)');
    }

    console.log('✅ Base de datos inicializada');
  } finally {
    client.release();
  }
}

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Trust proxy para Render/Railway
app.set('trust proxy', 1);

// Funciones auxiliares
function generarPassword() {
  return crypto.randomBytes(4).toString('hex').toUpperCase();
}

function generarToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Middleware de autenticación
async function verificarToken(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'No autorizado' });
  }

  const client = await pool.connect();
  try {
    const result = await client.query(`
      SELECT u.* FROM sesiones s
      JOIN usuarios u ON s.usuario_id = u.id
      WHERE s.token = $1 AND s.fecha_expiracion > NOW() AND u.activo = true
    `, [token]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Sesión expirada' });
    }

    req.user = result.rows[0];
    next();
  } finally {
    client.release();
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.rol)) {
      return res.status(403).json({ error: 'No tienes permisos' });
    }
    next();
  };
}

// ==================== API ROUTES ====================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const client = await pool.connect();

  try {
    const result = await client.query(
      'SELECT * FROM usuarios WHERE LOWER(email) = LOWER($1) AND password = $2 AND activo = true',
      [email, password]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const usuario = result.rows[0];
    const token = generarToken();
    const expiracion = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 días

    await client.query(
      'INSERT INTO sesiones (usuario_id, token, fecha_expiracion) VALUES ($1, $2, $3)',
      [usuario.id, token, expiracion]
    );

    res.json({
      token,
      usuario: {
        id: usuario.id,
        nombre: usuario.nombre,
        email: usuario.email,
        rol: usuario.rol,
        tempPassword: usuario.temp_password
      }
    });
  } finally {
    client.release();
  }
});

// Registro
app.post('/api/registro', async (req, res) => {
  const { nombre, email, telefono } = req.body;
  const client = await pool.connect();

  try {
    const existe = await client.query('SELECT id FROM usuarios WHERE LOWER(email) = LOWER($1)', [email]);
    if (existe.rows.length > 0) {
      return res.status(400).json({ error: 'El email ya está registrado' });
    }

    const tempPass = generarPassword();
    const result = await client.query(
      'INSERT INTO usuarios (nombre, email, telefono, password, rol, temp_password) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
      [nombre, email.toLowerCase(), telefono, tempPass, 'viewer', true]
    );

    io.emit('usuario_nuevo', { nombre, email });

    res.json({
      success: true,
      tempPassword: tempPass,
      mensaje: 'Usuario creado exitosamente'
    });
  } finally {
    client.release();
  }
});

// Cambiar contraseña (primera vez - con token)
app.post('/api/cambiar-password', async (req, res) => {
  const { token, nuevaPassword } = req.body;
  const client = await pool.connect();

  try {
    const sesion = await client.query(
      'SELECT usuario_id FROM sesiones WHERE token = $1 AND fecha_expiracion > NOW()',
      [token]
    );

    if (sesion.rows.length === 0) {
      return res.status(401).json({ error: 'Sesión inválida' });
    }

    await client.query(
      'UPDATE usuarios SET password = $1, temp_password = false WHERE id = $2',
      [nuevaPassword, sesion.rows[0].usuario_id]
    );

    res.json({ success: true });
  } finally {
    client.release();
  }
});

// Cambiar mi contraseña (usuario autenticado)
app.post('/api/cambiar-mi-password', verificarToken, async (req, res) => {
  const { passwordActual, passwordNueva } = req.body;
  const client = await pool.connect();

  try {
    // Verificar contraseña actual
    const usuario = await client.query(
      'SELECT password FROM usuarios WHERE id = $1',
      [req.user.id]
    );

    if (usuario.rows.length === 0 || usuario.rows[0].password !== passwordActual) {
      return res.status(400).json({ error: 'La contraseña actual es incorrecta' });
    }

    // Actualizar contraseña
    await client.query(
      'UPDATE usuarios SET password = $1 WHERE id = $2',
      [passwordNueva, req.user.id]
    );

    res.json({ success: true });
  } finally {
    client.release();
  }
});

// Verificar sesión
app.get('/api/verificar-sesion', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'No autorizado' });
  }

  const client = await pool.connect();
  try {
    const result = await client.query(`
      SELECT u.* FROM sesiones s
      JOIN usuarios u ON s.usuario_id = u.id
      WHERE s.token = $1 AND s.fecha_expiracion > NOW() AND u.activo = true
    `, [token]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Sesión expirada' });
    }

    const u = result.rows[0];
    res.json({
      usuario: {
        id: u.id,
        nombre: u.nombre,
        email: u.email,
        rol: u.rol,
        tempPassword: u.temp_password
      }
    });
  } finally {
    client.release();
  }
});

// Obtener usuarios (solo admin)
app.get('/api/usuarios', verificarToken, requireRole('admin'), async (req, res) => {
  const client = await pool.connect();
  try {
    const result = await client.query(
      'SELECT id, nombre, email, telefono, rol, temp_password, fecha_registro, activo FROM usuarios ORDER BY fecha_registro DESC'
    );
    res.json(result.rows);
  } finally {
    client.release();
  }
});

// Crear usuario (admin)
app.post('/api/usuarios', verificarToken, requireRole('admin'), async (req, res) => {
  const { nombre, email, rol } = req.body;
  const client = await pool.connect();

  try {
    const existe = await client.query('SELECT id FROM usuarios WHERE LOWER(email) = LOWER($1)', [email]);
    if (existe.rows.length > 0) {
      return res.status(400).json({ error: 'El email ya existe' });
    }

    const tempPass = generarPassword();
    await client.query(
      'INSERT INTO usuarios (nombre, email, password, rol, temp_password) VALUES ($1, $2, $3, $4, true)',
      [nombre, email.toLowerCase(), tempPass, rol || 'viewer']
    );

    io.emit('usuarios_actualizados');
    res.json({ success: true, tempPassword: tempPass });
  } finally {
    client.release();
  }
});

// Actualizar usuario
app.put('/api/usuarios/:id', verificarToken, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { rol, activo } = req.body;
  const client = await pool.connect();

  try {
    if (rol !== undefined) {
      await client.query('UPDATE usuarios SET rol = $1 WHERE id = $2', [rol, id]);
    }
    if (activo !== undefined) {
      await client.query('UPDATE usuarios SET activo = $1 WHERE id = $2', [activo, id]);
    }

    io.emit('usuarios_actualizados');
    res.json({ success: true });
  } finally {
    client.release();
  }
});

// Eliminar usuario
app.delete('/api/usuarios/:id', verificarToken, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();

  try {
    if (req.user.id === parseInt(id)) {
      return res.status(400).json({ error: 'No puedes eliminarte a ti mismo' });
    }

    await client.query('DELETE FROM usuarios WHERE id = $1', [id]);
    io.emit('usuarios_actualizados');
    res.json({ success: true });
  } finally {
    client.release();
  }
});

// Obtener datos de trámites
app.get('/api/tramites', async (req, res) => {
  const client = await pool.connect();
  try {
    const datos = await client.query('SELECT * FROM tramites_data');
    const proyecto = await client.query('SELECT * FROM proyecto_info WHERE id = 1');

    const tramitesObj = {};
    datos.rows.forEach(d => {
      if (!tramitesObj[d.tramite_id]) {
        tramitesObj[d.tramite_id] = { requisitos: {} };
      }
      tramitesObj[d.tramite_id].requisitos[d.requisito] = {
        estadoDoc: d.estado_doc,
        vigencia: d.vigencia,
        fechaVenc: d.fecha_venc,
        costoTramite: parseFloat(d.costo_tramite) || 0,
        pagoTramite: d.pago_tramite,
        costoGestor: parseFloat(d.costo_gestor) || 0,
        pagoGestor: d.pago_gestor,
        avance: parseFloat(d.avance) || 0,
        notas: d.notas
      };
    });

    res.json({ tramites: tramitesObj, proyecto: proyecto.rows[0] || null });
  } finally {
    client.release();
  }
});

// Actualizar requisito
app.post('/api/tramites/:tramiteId/requisitos', verificarToken, requireRole('admin', 'editor'), async (req, res) => {
  const { tramiteId } = req.params;
  const { requisito, datos } = req.body;
  const client = await pool.connect();

  try {
    await client.query(`
      INSERT INTO tramites_data (tramite_id, requisito, estado_doc, vigencia, fecha_venc, 
        costo_tramite, pago_tramite, costo_gestor, pago_gestor, avance, notas, actualizado_por)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      ON CONFLICT (tramite_id, requisito) DO UPDATE SET
        estado_doc = EXCLUDED.estado_doc,
        vigencia = EXCLUDED.vigencia,
        fecha_venc = EXCLUDED.fecha_venc,
        costo_tramite = EXCLUDED.costo_tramite,
        pago_tramite = EXCLUDED.pago_tramite,
        costo_gestor = EXCLUDED.costo_gestor,
        pago_gestor = EXCLUDED.pago_gestor,
        avance = EXCLUDED.avance,
        notas = EXCLUDED.notas,
        actualizado_por = EXCLUDED.actualizado_por,
        fecha_actualizacion = CURRENT_TIMESTAMP
    `, [
      tramiteId, requisito,
      datos.estadoDoc, datos.vigencia, datos.fechaVenc,
      datos.costoTramite || 0, datos.pagoTramite,
      datos.costoGestor || 0, datos.pagoGestor,
      datos.avance || 0, datos.notas,
      req.user.id
    ]);

    io.emit('tramite_actualizado', { tramiteId, requisito, datos });
    res.json({ success: true });
  } finally {
    client.release();
  }
});

// Actualizar info del proyecto
app.post('/api/proyecto', verificarToken, requireRole('admin'), async (req, res) => {
  const datos = req.body;
  const client = await pool.connect();

  try {
    await client.query(`
      INSERT INTO proyecto_info (id, nombre, ubicacion, responsable, fecha_inicio, 
        gestor_nombre, gestor_telefono, gestor_email, gestor_empresa)
      VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (id) DO UPDATE SET
        nombre = EXCLUDED.nombre,
        ubicacion = EXCLUDED.ubicacion,
        responsable = EXCLUDED.responsable,
        fecha_inicio = EXCLUDED.fecha_inicio,
        gestor_nombre = EXCLUDED.gestor_nombre,
        gestor_telefono = EXCLUDED.gestor_telefono,
        gestor_email = EXCLUDED.gestor_email,
        gestor_empresa = EXCLUDED.gestor_empresa
    `, [
      datos.nombre, datos.ubicacion, datos.responsable, datos.fechaInicio,
      datos.gestorNombre, datos.gestorTelefono, datos.gestorEmail, datos.gestorEmpresa
    ]);

    io.emit('proyecto_actualizado', datos);
    res.json({ success: true });
  } finally {
    client.release();
  }
});

// Logout
app.post('/api/logout', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token) {
    const client = await pool.connect();
    try {
      await client.query('DELETE FROM sesiones WHERE token = $1', [token]);
    } finally {
      client.release();
    }
  }
  res.json({ success: true });
});

// Catch-all para SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==================== SOCKET.IO ====================
io.on('connection', (socket) => {
  console.log('📱 Cliente conectado:', socket.id);
  socket.on('disconnect', () => {
    console.log('📴 Cliente desconectado:', socket.id);
  });
});

// ==================== INICIAR ====================
initDB().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║   🚀 CONTROL DE TRÁMITES C4 - SERVIDOR CLOUD              ║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log(`║   🌐 Servidor corriendo en puerto ${PORT}                    ║`);
    console.log('║                                                            ║');
    console.log('║   👤 Usuario por defecto:                                  ║');
    console.log('║      Email: admin@empresa.com                              ║');
    console.log('║      Contraseña: 1234                                      ║');
    console.log('╚════════════════════════════════════════════════════════════╝');
    console.log('');
  });
}).catch(err => {
  console.error('Error al inicializar:', err);
  process.exit(1);
});
