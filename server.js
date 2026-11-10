const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const db = require('./db');

const app = express();
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'cambia-esta-clave-secreta',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 8 * 3600 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Utilidades de fecha (YYYY-MM-DD) ----------
const pad = n => String(n).padStart(2, '0');
const fmt = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const hoy = () => fmt(new Date());
const hora = () => { const d = new Date(); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
const sumarDias = (iso, n) => { const [y, m, d] = iso.split('-').map(Number); return fmt(new Date(y, m - 1, d + n)); };
const DIAS_CUOTA = 30;

const auth = (req, res, next) =>
  req.session.adminId ? next() : res.status(401).json({ error: 'No autorizado' });

// ---------- Autenticación ----------
app.get('/api/auth/estado', (req, res) => {
  const { n } = db.prepare('SELECT COUNT(*) n FROM administradores').get();
  res.json({ hayAdmins: n > 0, logueado: !!req.session.adminId });
});

app.post('/api/auth/registro', (req, res) => {
  const { n } = db.prepare('SELECT COUNT(*) n FROM administradores').get();
  if (n > 0 && !req.session.adminId) return res.status(403).json({ error: 'Solo un administrador puede crear cuentas' });
  const usuario = String(req.body.usuario || '').trim();
  const password = String(req.body.password || '');
  if (usuario.length < 3 || password.length < 6)
    return res.status(400).json({ error: 'Usuario (mín. 3) y contraseña (mín. 6 caracteres)' });
  try {
    const r = db.prepare('INSERT INTO administradores(usuario, password_hash) VALUES(?,?)')
      .run(usuario, bcrypt.hashSync(password, 10));
    if (n === 0) req.session.adminId = r.lastInsertRowid;
    res.json({ ok: true });
  } catch (e) { res.status(409).json({ error: 'Ese usuario ya existe' }); }
});

app.post('/api/auth/login', (req, res) => {
  const a = db.prepare('SELECT * FROM administradores WHERE usuario = ?').get(String(req.body.usuario || '').trim());
  if (!a || !bcrypt.compareSync(String(req.body.password || ''), a.password_hash))
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  req.session.adminId = a.id;
  res.json({ ok: true });
});

app.post('/api/auth/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

// ---------- Consulta pública por DNI ----------
app.post('/api/consulta', (req, res) => {
  const dni = String(req.body.dni || '').trim();
  if (!/^\d{6,10}$/.test(dni)) return res.status(400).json({ acceso: false, mensaje: 'Ingresá un DNI válido (solo números)' });
  const c = db.prepare('SELECT * FROM clientes WHERE dni = ?').get(dni);
  if (!c) return res.json({ acceso: false, existe: false, mensaje: 'DNI no registrado. Acceso no permitido.' });

  const alDia = c.fecha_vencimiento >= hoy();
  db.prepare('UPDATE clientes SET estado = ? WHERE id = ?').run(alDia ? 1 : 0, c.id);
  if (alDia) {
    const ya = db.prepare('SELECT 1 FROM asistencias WHERE cliente_id = ? AND fecha_ingreso = ?').get(c.id, hoy());
    if (!ya) db.prepare('INSERT INTO asistencias(cliente_id, fecha_ingreso, hora_ingreso) VALUES(?,?,?)').run(c.id, hoy(), hora());
  }
  res.json({
    acceso: alDia, existe: true,
    nombre: `${c.nombre} ${c.apellido}`,
    estado: alDia ? 'Al día' : 'Deuda vencida',
    ultimoPago: c.fecha_ultimo_pago,
    vencimiento: c.fecha_vencimiento
  });
});

// ---------- ABM de clientes (admin) ----------
const validar = b => {
  const c = { dni: String(b.dni || '').trim(), nombre: String(b.nombre || '').trim(),
              apellido: String(b.apellido || '').trim(), celular: String(b.celular || '').trim() };
  if (!/^\d{6,10}$/.test(c.dni)) return { error: 'DNI inválido (6 a 10 números)' };
  if (!c.nombre || !c.apellido || !c.celular) return { error: 'DNI, nombre, apellido y celular son obligatorios' };
  return { c };
};

app.get('/api/clientes', auth, (req, res) => {
  const filas = db.prepare('SELECT * FROM clientes ORDER BY apellido, nombre').all();
  res.json(filas.map(c => ({ ...c, alDia: c.fecha_vencimiento >= hoy() })));
});

app.post('/api/clientes', auth, (req, res) => {
  const { c, error } = validar(req.body);
  if (error) return res.status(400).json({ error });
  const ultimo = hoy();
  try {
    db.prepare(`INSERT INTO clientes(dni,nombre,apellido,celular,fecha_ultimo_pago,fecha_vencimiento,estado)
                VALUES(?,?,?,?,?,?,1)`).run(c.dni, c.nombre, c.apellido, c.celular, ultimo, sumarDias(ultimo, DIAS_CUOTA));
    res.json({ ok: true });
  } catch (e) { res.status(409).json({ error: 'Ya existe un socio con ese DNI' }); }
});

app.put('/api/clientes/:id', auth, (req, res) => {
  const { c, error } = validar(req.body);
  if (error) return res.status(400).json({ error });
  try {
    db.prepare('UPDATE clientes SET dni=?, nombre=?, apellido=?, celular=? WHERE id=?')
      .run(c.dni, c.nombre, c.apellido, c.celular, req.params.id);
    res.json({ ok: true });
  } catch (e) { res.status(409).json({ error: 'Ya existe un socio con ese DNI' }); }
});

app.post('/api/clientes/:id/pago', auth, (req, res) => {
  const ultimo = hoy();
  db.prepare('UPDATE clientes SET fecha_ultimo_pago=?, fecha_vencimiento=?, estado=1 WHERE id=?')
    .run(ultimo, sumarDias(ultimo, DIAS_CUOTA), req.params.id);
  res.json({ ok: true });
});

app.delete('/api/clientes/:id', auth, (req, res) => {
  db.prepare('DELETE FROM clientes WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ---------- Estadísticas (admin) ----------
app.get('/api/estadisticas', auth, (req, res) => {
  const h = hoy(), mes = h.slice(0, 7), limite = sumarDias(h, -15), hace30 = sumarDias(h, -30);
  const uno = (sql, ...p) => db.prepare(sql).get(...p).n;

  const horasPico = db.prepare(`SELECT substr(hora_ingreso,1,2) AS hora, COUNT(*) AS ingresos
    FROM asistencias GROUP BY hora ORDER BY hora`).all();

  const inactivos = db.prepare(`SELECT c.dni, c.nombre, c.apellido, c.celular, MAX(a.fecha_ingreso) AS ultimo
    FROM clientes c LEFT JOIN asistencias a ON a.cliente_id = c.id
    GROUP BY c.id HAVING ultimo IS NULL OR ultimo < ? ORDER BY ultimo`).all(limite);

  const frecuencia = db.prepare(`SELECT c.nombre, c.apellido,
      SUM(CASE WHEN a.fecha_ingreso LIKE ? THEN 1 ELSE 0 END) AS visitasMes,
      SUM(CASE WHEN a.fecha_ingreso >= ? THEN 1 ELSE 0 END) AS visitas30
    FROM clientes c LEFT JOIN asistencias a ON a.cliente_id = c.id
    GROUP BY c.id ORDER BY visitasMes DESC`).all(mes + '%', hace30)
    .map(f => ({ ...f, porSemana: Math.round((f.visitas30 / 30) * 7 * 10) / 10 }));

  res.json({
    ingresosHoy: uno('SELECT COUNT(DISTINCT cliente_id) n FROM asistencias WHERE fecha_ingreso = ?', h),
    ingresosMes: uno('SELECT COUNT(*) n FROM asistencias WHERE fecha_ingreso LIKE ?', mes + '%'),
    sociosUnicos: uno('SELECT COUNT(*) n FROM clientes'),
    horasPico, inactivos, frecuencia
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`GymControl corriendo en http://localhost:${PORT}`));
