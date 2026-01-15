# 🌐 Control de Trámites C4 - Versión Cloud

Accesible desde **cualquier lugar del mundo** con WiFi o datos celulares.

---

## 🚀 DESPLIEGUE EN RENDER.COM (Gratis)

### Opción A: Despliegue Automático (Recomendado)

#### Paso 1: Subir a GitHub
1. Crea una cuenta en [github.com](https://github.com) si no tienes
2. Crea un nuevo repositorio llamado `tramites-c4`
3. Sube todos los archivos de esta carpeta

#### Paso 2: Conectar con Render
1. Ve a [render.com](https://render.com) y crea cuenta gratis
2. Click en **"New"** → **"Blueprint"**
3. Conecta tu cuenta de GitHub
4. Selecciona el repositorio `tramites-c4`
5. Click en **"Apply"**

#### Paso 3: ¡Listo!
Render creará automáticamente:
- ✅ Servidor web
- ✅ Base de datos PostgreSQL
- ✅ URL pública: `https://tramites-c4.onrender.com`

---

### Opción B: Despliegue Manual

#### Paso 1: Crear Base de Datos
1. En Render, click **"New"** → **"PostgreSQL"**
2. Nombre: `tramites-c4-db`
3. Plan: **Free**
4. Click **"Create Database"**
5. Copia el **"External Database URL"**

#### Paso 2: Crear Servidor Web
1. Click **"New"** → **"Web Service"**
2. Conecta tu repositorio de GitHub
3. Configuración:
   - **Name**: `tramites-c4`
   - **Runtime**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Plan**: `Free`

4. En **"Environment Variables"**, agrega:
   - `DATABASE_URL` = (pega la URL de la base de datos)

5. Click **"Create Web Service"**

---

## 📱 INSTALAR EN CELULARES

Una vez desplegado, tendrás una URL como:
```
https://tramites-c4.onrender.com
```

### iPhone
1. Abrir **Safari** (importante: debe ser Safari)
2. Ir a tu URL de Render
3. Tocar botón **"Compartir"** (cuadrado con flecha)
4. Seleccionar **"Agregar a pantalla de inicio"**
5. Nombrar la app y confirmar

### Android
1. Abrir **Chrome**
2. Ir a tu URL de Render
3. Tocar el banner **"Instalar app"** que aparece
4. O ir a Menú (⋮) → **"Instalar aplicación"**

---

## 👤 PRIMER USO

**Usuario administrador por defecto:**
- Email: `admin@empresa.com`
- Contraseña: `1234`

⚠️ **IMPORTANTE**: Cambia la contraseña del admin después del primer login.

---

## 🔧 CONFIGURACIÓN ADICIONAL

### Dominio Personalizado (Opcional)
En Render puedes agregar tu propio dominio:
1. Ve a tu Web Service
2. Click en **"Settings"**
3. En **"Custom Domains"**, agrega tu dominio
4. Configura los DNS según las instrucciones

### Variables de Entorno
| Variable | Descripción | Requerida |
|----------|-------------|-----------|
| `DATABASE_URL` | URL de PostgreSQL | ✅ Sí |
| `PORT` | Puerto del servidor | No (default: 3000) |
| `NODE_ENV` | Ambiente | No (default: production) |

---

## 💰 COSTOS

### Plan Gratuito de Render incluye:
- ✅ 750 horas de servidor/mes
- ✅ Base de datos PostgreSQL (90 días, luego se puede recrear)
- ✅ HTTPS automático
- ✅ Despliegue automático desde GitHub

### Limitaciones del plan gratuito:
- El servidor se "duerme" después de 15 min sin uso
- Al acceder después de dormir, tarda ~30 segundos en despertar
- La base de datos se borra después de 90 días (hacer backup)

### Plan Starter ($7/mes):
- Servidor siempre activo
- Sin límite de base de datos
- Mejor rendimiento

---

## 📋 ALTERNATIVAS A RENDER

### Railway.app
```bash
# Instalar CLI
npm install -g @railway/cli

# Login y deploy
railway login
railway init
railway up
```

### Fly.io
```bash
# Instalar flyctl
# Mac: brew install flyctl
# Windows: scoop install flyctl

flyctl launch
flyctl deploy
```

### Heroku (de pago ahora)
```bash
heroku create tramites-c4
heroku addons:create heroku-postgresql:mini
git push heroku main
```

---

## 🔄 ACTUALIZACIONES

Cada vez que hagas cambios y los subas a GitHub:
1. Render detecta automáticamente los cambios
2. Reconstruye y despliega la nueva versión
3. Sin downtime

---

## 🔒 SEGURIDAD

- ✅ HTTPS automático
- ✅ Contraseñas hasheadas (puedes mejorar con bcrypt)
- ✅ Tokens de sesión seguros
- ✅ Base de datos protegida

Para producción seria, considera:
1. Usar bcrypt para contraseñas
2. Implementar rate limiting
3. Agregar autenticación 2FA
4. Hacer backups regulares

---

## 📞 SOPORTE

Si tienes problemas:
1. Revisa los logs en Render Dashboard
2. Verifica que DATABASE_URL esté configurada
3. Asegúrate de que la base de datos esté activa

---

## 📁 ESTRUCTURA DEL PROYECTO

```
tramites-c4-cloud/
├── server.js           # Servidor Node.js
├── package.json        # Dependencias
├── render.yaml         # Config para Render
├── public/
│   ├── index.html      # Aplicación PWA
│   ├── manifest.json   # Config PWA
│   ├── sw.js           # Service Worker
│   └── icon-*.svg      # Iconos
└── README.md           # Este archivo
```

---

**¡Tu app estará disponible 24/7 desde cualquier parte del mundo!** 🌍
