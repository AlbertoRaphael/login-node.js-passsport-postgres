const LocalStrategy = require("passport-local").Strategy;
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");

function initialize(passport) {
  console.log("Initialized");

  const authenticateUser = (email, password, done) => {
    console.log(email, password);
    pool.query(
      `SELECT * FROM users WHERE email = $1`,
      [email],
      (err, results) => {
        if (err) {
          throw err;
        }
        console.log(results.rows);

        if (results.rows.length > 0) {
          const user = results.rows[0];

          bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
              console.log(err);
            }
            if (isMatch) {
              return done(null, user);
            } else {
              //password is incorrect
              return done(null, false, { message: "Password incorrecto" });
            }
          });
        } else {
          // No user
          return done(null, false, {
            message: "Ningún usuario con esa dirección de correo electrónico"
          });
        }
      }
    );
  };

  passport.use(
    new LocalStrategy(
      { usernameField: "email", passwordField: "password" },
      authenticateUser
    )
  );
  // Almacena los datos del usuario dentro de la sesión. serializeUser determina qué datos del usuario
  // deben ser almacenados en la sesión. El resultado del método serializeUser se adjunta
  // a la sesión como req.session.passport.user = {}. Aquí por ejemplo, sería (ya que proporcionamos
  // el id de usuario como clave) req.session.passport.user = {id: 'xyz'}
  passport.serializeUser((user, done) => done(null, user.id));

  // En deserializeUser esa clave es comparada con el array en memoria / 
  //base de datos o cualquier recurso de datos.
  // El objeto obtenido se adjunta al objeto de solicitud como req.user

  passport.deserializeUser((id, done) => {
    pool.query(`SELECT * FROM users WHERE id = $1`, [id], (err, results) => {
      if (err) {
        return done(err);
      }
      console.log(`ID is ${results.rows[0].id}`);
      return done(null, results.rows[0]);
    });
  });
}

module.exports = initialize;
