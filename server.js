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

// Base de datos PostgreSQL
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Inicializar base de datos
async function initDB() {
  const client = await pool.connect();
  try {
    // Migración: Agregar columnas nuevas si no existen (para bases de datos existentes)
    // Esto debe ejecutarse ANTES de crear las tablas para evitar conflictos
    await client.query(`
      DO $$ 
      BEGIN
        -- Agregar es_superadmin a usuarios si no existe
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'usuarios') THEN
          IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'usuarios' AND column_name = 'es_superadmin') THEN
            ALTER TABLE usuarios ADD COLUMN es_superadmin BOOLEAN DEFAULT false;
            RAISE NOTICE 'Columna es_superadmin agregada a usuarios';
          END IF;
        END IF;
      END $$;
    `);

    // Crear tablas si no existen
    await client.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        nombre TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        telefono TEXT,
        es_superadmin BOOLEAN DEFAULT false,
        temp_password BOOLEAN DEFAULT false,
        fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        activo BOOLEAN DEFAULT true
      );

      CREATE TABLE IF NOT EXISTS proyectos (
        id SERIAL PRIMARY KEY,
        nombre TEXT NOT NULL,
        ubicacion TEXT,
        descripcion TEXT,
        responsable TEXT,
        fecha_inicio DATE,
        activo BOOLEAN DEFAULT true,
        creado_por INTEGER,
        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS proyecto_usuarios (
        id SERIAL PRIMARY KEY,
        proyecto_id INTEGER,
        usuario_id INTEGER,
        rol TEXT DEFAULT 'viewer',
        fecha_asignacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(proyecto_id, usuario_id)
      );

      CREATE TABLE IF NOT EXISTS tramites_data (
        id SERIAL PRIMARY KEY,
        proyecto_id INTEGER,
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
        fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS archivos (
        id SERIAL PRIMARY KEY,
        proyecto_id INTEGER,
        tramite_id INTEGER NOT NULL,
        requisito TEXT NOT NULL,
        nombre_archivo TEXT NOT NULL,
        tipo_archivo TEXT NOT NULL,
        tamanio INTEGER,
        contenido TEXT NOT NULL,
        subido_por INTEGER,
        fecha_subida TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS sesiones (
        id SERIAL PRIMARY KEY,
        usuario_id INTEGER,
        token TEXT UNIQUE,
        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        fecha_expiracion TIMESTAMP
      );
    `);

    // Agregar columna proyecto_id a tramites_data si no existe (migración)
    await client.query(`
      DO $$ 
      BEGIN
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'tramites_data') THEN
          IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'tramites_data' AND column_name = 'proyecto_id') THEN
            ALTER TABLE tramites_data ADD COLUMN proyecto_id INTEGER;
          END IF;
        END IF;
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'archivos') THEN
          IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'archivos' AND column_name = 'proyecto_id') THEN
            ALTER TABLE archivos ADD COLUMN proyecto_id INTEGER;
          END IF;
        END IF;
      END $$;
    `);

    console.log('✅ Base de datos inicializada');

    // Solo Jose Jimenez es superadmin
    const joseCheck = await client.query('SELECT id FROM usuarios WHERE email = $1', ['josejimenezsalinas81@gmail.com']);
    if (joseCheck.rows.length === 0) {
      await client.query(
        'INSERT INTO usuarios (nombre, email, password, es_superadmin, temp_password) VALUES ($1, $2, $3, $4, $5)',
        ['Jose Jimenez', 'josejimenezsalinas81@gmail.com', 'Jo$e1687Wendy0421', true, false]
      );
      console.log('✅ Usuario administrador Jose creado');
    } else {
      await client.query('UPDATE usuarios SET es_superadmin = true WHERE email = $1', ['josejimenezsalinas81@gmail.com']);
    }

    // Asegurar que ningún otro usuario sea superadmin
    await client.query('UPDATE usuarios SET es_superadmin = false WHERE email != $1', ['josejimenezsalinas81@gmail.com']);

    console.log('✅ Administrador configurado');
  } finally {
    client.release();
  }
}

// Middleware - Límite de 150MB para archivos
app.use(express.json({ limit: '150mb' }));
app.use(express.urlencoded({ limit: '150mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
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

// Verificar permiso en proyecto
async function verificarPermisoProyecto(userId, proyectoId, rolesPermitidos, client) {
  // Verificar si es superadmin
  const userCheck = await client.query('SELECT es_superadmin FROM usuarios WHERE id = $1', [userId]);
  if (userCheck.rows[0]?.es_superadmin) {
    return { permitido: true, rol: 'admin' };
  }

  // Verificar rol en proyecto
  const permiso = await client.query(
    'SELECT rol FROM proyecto_usuarios WHERE usuario_id = $1 AND proyecto_id = $2',
    [userId, proyectoId]
  );

  if (permiso.rows.length === 0) {
    return { permitido: false, rol: null };
  }

  const rol = permiso.rows[0].rol;
  if (rolesPermitidos.includes(rol)) {
    return { permitido: true, rol };
  }

  return { permitido: false, rol };
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
    const expiracion = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

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
        esSuperadmin: usuario.es_superadmin,
        tempPassword: usuario.temp_password
      }
    });
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
        esSuperadmin: u.es_superadmin,
        tempPassword: u.temp_password
      }
    });
  } finally {
    client.release();
  }
});

// Registro público de usuarios
app.post('/api/registro', async (req, res) => {
  const { nombre, email, telefono, password } = req.body;
  const client = await pool.connect();

  try {
    if (!nombre || !email || !password) {
      return res.status(400).json({ error: 'Nombre, email y contraseña son obligatorios' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
    }

    const existe = await client.query('SELECT id FROM usuarios WHERE LOWER(email) = LOWER($1)', [email]);
    if (existe.rows.length > 0) {
      return res.status(400).json({ error: 'Este correo ya está registrado' });
    }

    await client.query(
      'INSERT INTO usuarios (nombre, email, telefono, password, es_superadmin, temp_password) VALUES ($1, $2, $3, $4, $5, $6)',
      [nombre, email.toLowerCase(), telefono || null, password, false, false]
    );

    io.emit('usuario_registrado', { nombre, email });

    res.json({
      success: true,
      mensaje: 'Cuenta creada exitosamente. El administrador debe asignarte a un proyecto.'
    });
  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ error: 'Error al crear la cuenta' });
  } finally {
    client.release();
  }
});

// Cambiar contraseña (primera vez)
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

// Cambiar mi contraseña
app.post('/api/cambiar-mi-password', verificarToken, async (req, res) => {
  const { passwordActual, passwordNueva } = req.body;
  const client = await pool.connect();

  try {
    const usuario = await client.query(
      'SELECT password FROM usuarios WHERE id = $1',
      [req.user.id]
    );

    if (usuario.rows.length === 0 || usuario.rows[0].password !== passwordActual) {
      return res.status(400).json({ error: 'La contraseña actual es incorrecta' });
    }

    await client.query(
      'UPDATE usuarios SET password = $1 WHERE id = $2',
      [passwordNueva, req.user.id]
    );

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

// ==================== PROYECTOS ====================

// Obtener proyectos del usuario
app.get('/api/proyectos', verificarToken, async (req, res) => {
  const client = await pool.connect();
  try {
    let proyectos;
    
    if (req.user.es_superadmin) {
      // Superadmin ve todos los proyectos
      proyectos = await client.query(`
        SELECT p.*, u.nombre as creado_por_nombre,
          (SELECT COUNT(*) FROM proyecto_usuarios WHERE proyecto_id = p.id) as total_usuarios
        FROM proyectos p
        LEFT JOIN usuarios u ON p.creado_por = u.id
        WHERE p.activo = true
        ORDER BY p.fecha_creacion DESC
      `);
    } else {
      // Usuario normal ve solo sus proyectos asignados
      proyectos = await client.query(`
        SELECT p.*, pu.rol as mi_rol, u.nombre as creado_por_nombre
        FROM proyectos p
        JOIN proyecto_usuarios pu ON p.id = pu.proyecto_id
        LEFT JOIN usuarios u ON p.creado_por = u.id
        WHERE pu.usuario_id = $1 AND p.activo = true
        ORDER BY p.fecha_creacion DESC
      `, [req.user.id]);
    }

    res.json(proyectos.rows);
  } finally {
    client.release();
  }
});

// Crear proyecto (solo superadmin)
app.post('/api/proyectos', verificarToken, async (req, res) => {
  if (!req.user.es_superadmin) {
    return res.status(403).json({ error: 'Solo el administrador puede crear proyectos' });
  }

  const { nombre, ubicacion, descripcion, responsable, fechaInicio } = req.body;
  const client = await pool.connect();

  try {
    const result = await client.query(
      `INSERT INTO proyectos (nombre, ubicacion, descripcion, responsable, fecha_inicio, creado_por)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [nombre, ubicacion, descripcion, responsable, fechaInicio, req.user.id]
    );

    // Asignar automáticamente al creador como admin del proyecto
    await client.query(
      'INSERT INTO proyecto_usuarios (proyecto_id, usuario_id, rol) VALUES ($1, $2, $3)',
      [result.rows[0].id, req.user.id, 'admin']
    );

    io.emit('proyecto_creado');
    res.json({ success: true, id: result.rows[0].id });
  } finally {
    client.release();
  }
});

// Actualizar proyecto
app.put('/api/proyectos/:id', verificarToken, async (req, res) => {
  const { id } = req.params;
  const { nombre, ubicacion, descripcion, responsable, fechaInicio } = req.body;
  const client = await pool.connect();

  try {
    const permiso = await verificarPermisoProyecto(req.user.id, id, ['admin'], client);
    if (!permiso.permitido) {
      return res.status(403).json({ error: 'No tienes permisos para editar este proyecto' });
    }

    await client.query(
      `UPDATE proyectos SET nombre = $1, ubicacion = $2, descripcion = $3, 
       responsable = $4, fecha_inicio = $5 WHERE id = $6`,
      [nombre, ubicacion, descripcion, responsable, fechaInicio, id]
    );

    io.emit('proyecto_actualizado', { proyectoId: id });
    res.json({ success: true });
  } finally {
    client.release();
  }
});

// Eliminar proyecto (solo superadmin)
app.delete('/api/proyectos/:id', verificarToken, async (req, res) => {
  if (!req.user.es_superadmin) {
    return res.status(403).json({ error: 'Solo el administrador puede eliminar proyectos' });
  }

  const { id } = req.params;
  const client = await pool.connect();

  try {
    await client.query('UPDATE proyectos SET activo = false WHERE id = $1', [id]);
    io.emit('proyecto_eliminado', { proyectoId: id });
    res.json({ success: true });
  } finally {
    client.release();
  }
});

// ==================== USUARIOS DE PROYECTO ====================

// Obtener usuarios de un proyecto
app.get('/api/proyectos/:proyectoId/usuarios', verificarToken, async (req, res) => {
  const { proyectoId } = req.params;
  const client = await pool.connect();

  try {
    const permiso = await verificarPermisoProyecto(req.user.id, proyectoId, ['admin'], client);
    if (!permiso.permitido) {
      return res.status(403).json({ error: 'No tienes permisos' });
    }

    const usuarios = await client.query(`
      SELECT u.id, u.nombre, u.email, u.telefono, pu.rol, pu.fecha_asignacion
      FROM proyecto_usuarios pu
      JOIN usuarios u ON pu.usuario_id = u.id
      WHERE pu.proyecto_id = $1 AND u.activo = true
      ORDER BY pu.fecha_asignacion
    `, [proyectoId]);

    res.json(usuarios.rows);
  } finally {
    client.release();
  }
});

// Agregar usuario a proyecto
app.post('/api/proyectos/:proyectoId/usuarios', verificarToken, async (req, res) => {
  const { proyectoId } = req.params;
  const { email, rol } = req.body;
  const client = await pool.connect();

  try {
    const permiso = await verificarPermisoProyecto(req.user.id, proyectoId, ['admin'], client);
    if (!permiso.permitido) {
      return res.status(403).json({ error: 'No tienes permisos' });
    }

    // Buscar usuario por email
    let usuario = await client.query('SELECT id FROM usuarios WHERE LOWER(email) = LOWER($1)', [email]);
    
    let tempPassword = null;
    if (usuario.rows.length === 0) {
      // Crear usuario nuevo
      tempPassword = generarPassword();
      const nuevoUsuario = await client.query(
        'INSERT INTO usuarios (nombre, email, password, temp_password) VALUES ($1, $2, $3, true) RETURNING id',
        [email.split('@')[0], email.toLowerCase(), tempPassword]
      );
      usuario = { rows: [{ id: nuevoUsuario.rows[0].id }] };
    }

    // Verificar si ya está asignado
    const yaAsignado = await client.query(
      'SELECT id FROM proyecto_usuarios WHERE proyecto_id = $1 AND usuario_id = $2',
      [proyectoId, usuario.rows[0].id]
    );

    if (yaAsignado.rows.length > 0) {
      return res.status(400).json({ error: 'El usuario ya está asignado a este proyecto' });
    }

    // Asignar al proyecto
    await client.query(
      'INSERT INTO proyecto_usuarios (proyecto_id, usuario_id, rol) VALUES ($1, $2, $3)',
      [proyectoId, usuario.rows[0].id, rol || 'viewer']
    );

    io.emit('usuarios_proyecto_actualizados', { proyectoId });
    res.json({ success: true, tempPassword });
  } finally {
    client.release();
  }
});

// Cambiar rol de usuario en proyecto
app.put('/api/proyectos/:proyectoId/usuarios/:usuarioId', verificarToken, async (req, res) => {
  const { proyectoId, usuarioId } = req.params;
  const { rol } = req.body;
  const client = await pool.connect();

  try {
    const permiso = await verificarPermisoProyecto(req.user.id, proyectoId, ['admin'], client);
    if (!permiso.permitido) {
      return res.status(403).json({ error: 'No tienes permisos' });
    }

    await client.query(
      'UPDATE proyecto_usuarios SET rol = $1 WHERE proyecto_id = $2 AND usuario_id = $3',
      [rol, proyectoId, usuarioId]
    );

    io.emit('usuarios_proyecto_actualizados', { proyectoId });
    res.json({ success: true });
  } finally {
    client.release();
  }
});

// Remover usuario de proyecto
app.delete('/api/proyectos/:proyectoId/usuarios/:usuarioId', verificarToken, async (req, res) => {
  const { proyectoId, usuarioId } = req.params;
  const client = await pool.connect();

  try {
    const permiso = await verificarPermisoProyecto(req.user.id, proyectoId, ['admin'], client);
    if (!permiso.permitido) {
      return res.status(403).json({ error: 'No tienes permisos' });
    }

    // No permitir removerse a sí mismo si es el único admin
    if (parseInt(usuarioId) === req.user.id) {
      const otrosAdmins = await client.query(
        `SELECT COUNT(*) FROM proyecto_usuarios WHERE proyecto_id = $1 AND rol = 'admin' AND usuario_id != $2`,
        [proyectoId, usuarioId]
      );
      if (parseInt(otrosAdmins.rows[0].count) === 0 && !req.user.es_superadmin) {
        return res.status(400).json({ error: 'No puedes removerte, eres el único administrador del proyecto' });
      }
    }

    await client.query(
      'DELETE FROM proyecto_usuarios WHERE proyecto_id = $1 AND usuario_id = $2',
      [proyectoId, usuarioId]
    );

    io.emit('usuarios_proyecto_actualizados', { proyectoId });
    res.json({ success: true });
  } finally {
    client.release();
  }
});

// ==================== TODOS LOS USUARIOS (solo superadmin) ====================

app.get('/api/usuarios', verificarToken, async (req, res) => {
  if (!req.user.es_superadmin) {
    return res.status(403).json({ error: 'No autorizado' });
  }

  const client = await pool.connect();
  try {
    const result = await client.query(
      `SELECT id, nombre, email, telefono, es_superadmin, temp_password, fecha_registro, activo 
       FROM usuarios WHERE activo = true ORDER BY fecha_registro DESC`
    );
    res.json(result.rows);
  } finally {
    client.release();
  }
});

// Crear usuario global (solo admin puede crear)
app.post('/api/usuarios', verificarToken, async (req, res) => {
  if (!req.user.es_superadmin) {
    return res.status(403).json({ error: 'No autorizado' });
  }

  const { nombre, email } = req.body;
  const client = await pool.connect();

  try {
    const existe = await client.query('SELECT id FROM usuarios WHERE LOWER(email) = LOWER($1)', [email]);
    if (existe.rows.length > 0) {
      return res.status(400).json({ error: 'El email ya existe' });
    }

    const tempPass = generarPassword();
    await client.query(
      'INSERT INTO usuarios (nombre, email, password, es_superadmin, temp_password) VALUES ($1, $2, $3, $4, true)',
      [nombre, email.toLowerCase(), tempPass, false]
    );

    res.json({ success: true, tempPassword: tempPass });
  } finally {
    client.release();
  }
});

// Eliminar usuario global
app.delete('/api/usuarios/:id', verificarToken, async (req, res) => {
  if (!req.user.es_superadmin) {
    return res.status(403).json({ error: 'No autorizado' });
  }

  const { id } = req.params;
  const client = await pool.connect();

  try {
    if (req.user.id === parseInt(id)) {
      return res.status(400).json({ error: 'No puedes eliminarte a ti mismo' });
    }

    await client.query('UPDATE usuarios SET activo = false WHERE id = $1', [id]);
    res.json({ success: true });
  } finally {
    client.release();
  }
});

// Obtener proyectos asignados a un usuario específico
app.get('/api/usuarios/:id/proyectos', verificarToken, async (req, res) => {
  if (!req.user.es_superadmin) {
    return res.status(403).json({ error: 'No autorizado' });
  }

  const { id } = req.params;
  const client = await pool.connect();

  try {
    const result = await client.query(`
      SELECT p.id, p.nombre, pu.rol 
      FROM proyecto_usuarios pu
      JOIN proyectos p ON pu.proyecto_id = p.id
      WHERE pu.usuario_id = $1 AND p.activo = true
      ORDER BY p.nombre
    `, [id]);
    
    res.json(result.rows);
  } finally {
    client.release();
  }
});

// ==================== TRÁMITES DE PROYECTO ====================

// Obtener datos de trámites de un proyecto
app.get('/api/proyectos/:proyectoId/tramites', verificarToken, async (req, res) => {
  const { proyectoId } = req.params;
  const client = await pool.connect();

  try {
    const permiso = await verificarPermisoProyecto(req.user.id, proyectoId, ['admin', 'editor', 'viewer'], client);
    if (!permiso.permitido) {
      return res.status(403).json({ error: 'No tienes acceso a este proyecto' });
    }

    const datos = await client.query(
      'SELECT * FROM tramites_data WHERE proyecto_id = $1',
      [proyectoId]
    );

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

    res.json({ tramites: tramitesObj, miRol: permiso.rol });
  } finally {
    client.release();
  }
});

// Actualizar requisito de proyecto
app.post('/api/proyectos/:proyectoId/tramites/:tramiteId/requisitos', verificarToken, async (req, res) => {
  const { proyectoId, tramiteId } = req.params;
  const { requisito, datos } = req.body;
  const client = await pool.connect();

  try {
    const permiso = await verificarPermisoProyecto(req.user.id, proyectoId, ['admin', 'editor'], client);
    if (!permiso.permitido) {
      return res.status(403).json({ error: 'No tienes permisos para editar' });
    }

    await client.query(`
      INSERT INTO tramites_data (proyecto_id, tramite_id, requisito, estado_doc, vigencia, fecha_venc, 
        costo_tramite, pago_tramite, costo_gestor, pago_gestor, avance, notas, actualizado_por)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      ON CONFLICT (proyecto_id, tramite_id, requisito) DO UPDATE SET
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
      proyectoId, tramiteId, requisito,
      datos.estadoDoc, datos.vigencia, datos.fechaVenc,
      datos.costoTramite || 0, datos.pagoTramite,
      datos.costoGestor || 0, datos.pagoGestor,
      datos.avance || 0, datos.notas,
      req.user.id
    ]);

    io.emit('tramite_actualizado', { proyectoId, tramiteId, requisito, datos });
    res.json({ success: true });
  } finally {
    client.release();
  }
});

// ==================== ARCHIVOS DE PROYECTO ====================

// Subir archivo
app.post('/api/proyectos/:proyectoId/archivos', verificarToken, async (req, res) => {
  const { proyectoId } = req.params;
  const { tramiteId, requisito, nombreArchivo, tipoArchivo, contenido } = req.body;
  const client = await pool.connect();

  try {
    const permiso = await verificarPermisoProyecto(req.user.id, proyectoId, ['admin'], client);
    if (!permiso.permitido) {
      return res.status(403).json({ error: 'Solo administradores pueden subir archivos' });
    }

    const tiposPermitidos = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    if (!tiposPermitidos.includes(tipoArchivo)) {
      return res.status(400).json({ error: 'Solo se permiten archivos PDF y Word' });
    }

    if (contenido.length > 140000000) {
      return res.status(400).json({ error: 'Archivo demasiado grande. Máximo 100MB.' });
    }

    const result = await client.query(
      `INSERT INTO archivos (proyecto_id, tramite_id, requisito, nombre_archivo, tipo_archivo, tamanio, contenido, subido_por)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
      [proyectoId, tramiteId, requisito, nombreArchivo, tipoArchivo, contenido.length, contenido, req.user.id]
    );

    io.emit('archivo_subido', { proyectoId, tramiteId, requisito });
    res.json({ success: true, id: result.rows[0].id });
  } catch (error) {
    console.error('Error al subir archivo:', error);
    res.status(500).json({ error: 'Error al subir el archivo' });
  } finally {
    client.release();
  }
});

// IMPORTANTE: Esta ruta debe ir ANTES de /:tramiteId/:requisito
// Descargar/Ver archivo - devuelve JSON con contenido
app.get('/api/proyectos/:proyectoId/archivos/descargar/:id', verificarToken, async (req, res) => {
  const { proyectoId, id } = req.params;
  const client = await pool.connect();

  try {
    const permiso = await verificarPermisoProyecto(req.user.id, proyectoId, ['admin', 'editor', 'viewer'], client);
    if (!permiso.permitido) {
      return res.status(403).json({ error: 'No tienes acceso' });
    }

    const result = await client.query(
      'SELECT nombre_archivo, tipo_archivo, contenido FROM archivos WHERE id = $1 AND proyecto_id = $2',
      [id, proyectoId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Archivo no encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error al descargar:', error);
    res.status(500).json({ error: 'Error al descargar el archivo' });
  } finally {
    client.release();
  }
});

// Listar archivos de un requisito
app.get('/api/proyectos/:proyectoId/archivos/:tramiteId/:requisito', verificarToken, async (req, res) => {
  const { proyectoId, tramiteId, requisito } = req.params;
  const client = await pool.connect();

  try {
    const permiso = await verificarPermisoProyecto(req.user.id, proyectoId, ['admin', 'editor', 'viewer'], client);
    if (!permiso.permitido) {
      return res.status(403).json({ error: 'No tienes acceso' });
    }

    const result = await client.query(
      `SELECT a.id, a.nombre_archivo, a.tipo_archivo, a.tamanio, a.fecha_subida, u.nombre as subido_por_nombre
       FROM archivos a
       LEFT JOIN usuarios u ON a.subido_por = u.id
       WHERE a.proyecto_id = $1 AND a.tramite_id = $2 AND a.requisito = $3
       ORDER BY a.fecha_subida DESC`,
      [proyectoId, tramiteId, requisito]
    );

    res.json(result.rows);
  } finally {
    client.release();
  }
});

// Eliminar archivo
app.delete('/api/proyectos/:proyectoId/archivos/:id', verificarToken, async (req, res) => {
  const { proyectoId, id } = req.params;
  const client = await pool.connect();

  try {
    const permiso = await verificarPermisoProyecto(req.user.id, proyectoId, ['admin'], client);
    if (!permiso.permitido) {
      return res.status(403).json({ error: 'Solo administradores pueden eliminar archivos' });
    }

    await client.query('DELETE FROM archivos WHERE id = $1 AND proyecto_id = $2', [id, proyectoId]);
    io.emit('archivo_eliminado', { proyectoId });
    res.json({ success: true });
  } finally {
    client.release();
  }
});

// Catch-all para SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Socket.IO
io.on('connection', (socket) => {
  console.log('📱 Cliente conectado:', socket.id);
  socket.on('disconnect', () => {
    console.log('📴 Cliente desconectado:', socket.id);
  });
});

// Iniciar servidor
initDB().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║   🚀 CONTROL DE TRÁMITES C4 - MULTI-PROYECTO              ║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log(`║   🌐 Servidor corriendo en puerto ${PORT}                    ║`);
    console.log('║                                                            ║');
    console.log('║   👑 Administrador:                                        ║');
    console.log('║      josejimenezsalinas81@gmail.com                        ║');
    console.log('╚════════════════════════════════════════════════════════════╝');
    console.log('');
  });
}).catch(err => {
  console.error('Error al inicializar:', err);
  process.exit(1);
});

