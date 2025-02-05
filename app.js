// ==========================================
// Importación de módulos y configuración inicial
// ==========================================
require('dotenv').config();
const express = require('express');
const path = require('path');
const morgan = require('morgan');
const fs = require('fs');
const mongoose = require('mongoose');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const bcrypt = require('bcrypt');
const flash = require('connect-flash');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const bodyParser = require('body-parser');

// Importación de modelos
const User = require('./models/user');
const Activity = require('./models/Activity');

// Inicialización de la aplicación
const app = express();
const PORT = process.env.PORT;

// ==========================================
// Configuración de seguridad
// ==========================================
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);
app.use(helmet());

// ==========================================
// Configuración de la base de datos
// ==========================================
const dbURI = process.env.MONGODB_URI;
mongoose
  .connect(dbURI)
  .then(() => app.listen(PORT, () => {
    console.log('Servidor iniciado');  
  }))
  .catch(() => process.exit(1));
// ==========================================
// Configuración del motor de vistas
// ==========================================
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'vistas'));



// ==========================================
// Middleware generales
// ==========================================
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Configuración de logs
const accessLogStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' });
app.use(morgan('tiny', { stream: accessLogStream }));

// ==========================================
// Configuración de sesiones y autenticación
// ==========================================
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { maxAge: 1000 * 60 * 30 }
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// Configuración de Passport
passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, async (email, password, done) => {
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return done(null, false, { message: 'Usuario no encontrado' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      let activity = await Activity.findOne({ userId: user._id });
      if (activity) {
        activity.failedAttempts += 1;
        await activity.save();
      } else {
        await Activity.create({
          userId: user._id,
          lastLogin: null,
          failedAttempts: 1,
          isLoggedIn: false
        });
      }
      return done(null, false, { message: 'Contraseña incorrecta' });
    }
    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

// ==========================================
// Middleware personalizados
// ==========================================
const updateActivity = async (req, res, next) => {
  if (req.session.userId) {
    try {
      let activity = await Activity.findOne({ userId: req.session.userId });
      if (activity) {
        activity.lastLogin = Date.now();
        activity.isLoggedIn = true;
        await activity.save();
      } else {
        await Activity.create({
          userId: req.session.userId,
          lastLogin: Date.now(),
          isLoggedIn: true
        });
      }
    } catch (err) {}
  }
  next();
};

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).render('errorAuth', { title: 'No autenticado', message: 'Debes iniciar sesión para acceder' });
}

app.use((req, res, next) => {
  res.locals.user = req.user || null;
  res.locals.message = req.flash();
  next();
});

// ==========================================
// Rutas de la aplicación
// ==========================================

// Rutas públicas
app.get('/', (req, res) => {
  res.render('main2', { 
    user: req.user, 
    title: 'Bienvenido a la plataforma'
  });
});

app.get('/about-me', (req, res) => {
  res.redirect('/about');
});

// Rutas de autenticación
app.get('/sign-up', (req, res) => {
  res.render('sign-up', { title: 'Crear cuenta' });
});

app.post('/sign-up', async (req, res) => {
  try {
    const { email, password, name, surname, dob, gender } = req.body;

    if (!password) {
      return res.status(400).send('La contraseña es requerida');
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).send('El usuario ya existe');
    }

    const newUser = new User({
      email,
      password,
      name,
      surname,
      dob,
      gender,
    });

    await newUser.save();

    await Activity.create({
      userId: newUser._id,
      lastLogin: Date.now(),
      failedAttempts: 0,
      isLoggedIn: false
    });

    res.redirect('/login');
  } catch (error) {
    res.status(500).send('Error al crear el usuario');
  }
});

app.get('/login', (req, res) => {
  res.render('login', { title: 'Iniciar sesion' });
});

app.post('/login', passport.authenticate('local', {
  failureRedirect: '/login',
  failureFlash: true
}), async (req, res) => {
  req.session.userId = req.user._id;
  await updateActivity(req, res, () => {});
  res.redirect('/basededatos');
});

app.get('/logout', (req, res) => {
  req.logout((error) => {
    if (error) {
      return res.status(500).send('Error al cerrar sesión');
    }
    res.redirect('/');
  });
});

// Rutas protegidas
app.get('/basededatos', ensureAuthenticated, async (req, res) => {
  try {
    const users = await User.find().select('-password -__v');
    const activities = await Activity.find().populate('userId', '-password -__v');
    res.render('basededatos', { 
      title: 'Base de Datos de Usuarios',
      user: req.user,
      users,
      activities: activities || []
    });
  } catch (error) {
    res.status(500).send('Error al cargar los usuarios');
  }
});

app.get('/user-activity', ensureAuthenticated, (req, res) => {
  Activity.find()
    .populate('userId', '-password -__v')
    .then(activities => {
      res.render('basededatos', { 
        title: 'Actividades de Usuario',
        activities,
        user: req.user,
        users: [] 
      });
    })
    .catch(() => {
      res.status(500).send('Error al cargar las actividades');
    });
});

app.get('/edit-user/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send('Usuario no encontrado');
    }
    res.render('edit-user', { user, title: 'Editar Usuario' });
  } catch {
    res.status(500).send('Error al cargar el formulario de edición');
  }
});

app.post('/edit-user/:id', async (req, res) => {
  try {
    const { name, surname, email, dob, gender } = req.body;
    const updateFields = {};
    if (name) updateFields.name = name;
    if (surname) updateFields.surname = surname;
    if (email) updateFields.email = email;
    if (dob) updateFields.dob = new Date(dob);
    if (gender) updateFields.gender = gender;

    const updatedUser = await User.findByIdAndUpdate(req.params.id, updateFields, { new: true });
    if (!updatedUser) {
      return res.status(404).send('Usuario no encontrado.');
    }
    res.redirect('/basededatos');
  } catch (error) {
    res.status(500).send('Error al actualizar el usuario.');
  }
});

app.post('/delete-user/:id', async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).send('Usuario no encontrado');
    }
    await Activity.deleteMany({ userId: user._id });
    res.redirect('/basededatos');
  } catch (error) {
    res.status(500).send('Error al eliminar el usuario');
  }
});

// Rutas de error
app.get('/error', (req, res) => {
  res.render('errorAuth', { 
    title: 'Error de autenticación', 
    user: req.user
  });
});

// Middleware para manejar 404
app.use((req, res) => {
  res.status(404).render('404', { title: 'Página no encontrada' });
});