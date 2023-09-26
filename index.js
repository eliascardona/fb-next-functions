const admin = require('firebase-admin');
const { applicationDefault } = require('firebase-admin/app');
const { onRequest } = require('firebase-functions/v2/https');

const ROLES = {
  ADMIN: 'administrador',
  CLIENT: 'cliente',
  GUEST: 'invitado',
};

admin.initializeApp({
  credential: applicationDefault(),
});

exports.setRolAdministrador = onRequest(
  { cors: [/firebase\.com$/, 'http://localhost:3000'] },
  (req, res) => {
    console.log('LOG: rol administrador');
    if (
      !req.headers.authorization ||
      !req.headers.authorization.startsWith('Bearer ')
    ) {
      return res.status(403).send(JSON.stringify({ status: 'Unauthorized' }));
    }

    const token = req.headers.authorization.split('Bearer ')[1];

    admin
      .auth()
      .verifyIdToken(token)
      .then((decodedToken) => {
        const uid = decodedToken.uid;
        admin
          .auth()
          .setCustomUserClaims(uid, { rol: ROLES.ADMIN })
          .then(
            admin
              .auth()
              .getUser(uid)
              .then((user) => console.log(user.email, user.customClaims))
          );
      })
      .catch((error) => {
        // The token is invalid or has expired, so return an error
        return res.status(403).send(JSON.stringify({ status: 'Unauthorized' }));
      });
    res.status(200).send(JSON.stringify({ status: 'success' }));
  }
);

exports.setRolCliente = onRequest(
  { cors: [/firebase\.com$/, 'http://localhost:3000'] },
  (req, res) => {
    console.log('LOG: rol cliente');
    if (
      !req.headers.authorization ||
      !req.headers.authorization.startsWith('Bearer ')
    ) {
      return res.status(403).send(JSON.stringify({ status: 'Unauthorized' }));
    }

    const token = req.headers.authorization.split('Bearer ')[1];

    admin
      .auth()
      .verifyIdToken(token)
      .then((decodedToken) => {
        const uid = decodedToken.uid;
        admin
          .auth()
          .setCustomUserClaims(uid, { rol: ROLES.CLIENT })
          .then(
            admin
              .auth()
              .getUser(uid)
              .then((user) => console.log(user.email, user.customClaims))
          );
      })
      .catch((error) => {
        // The token is invalid or has expired, so return an error
        return res.status(403).send(JSON.stringify({ status: 'Unauthorized' }));
      });
    res.status(200).send(JSON.stringify({ status: 'success' }));
  }
);

exports.setRolInvitado = onRequest(
  { cors: [/firebase\.com$/, 'http://localhost:3000'] },
  (req, res) => {
    console.log('LOG: rol visitante');
    if (
      !req.headers.authorization ||
      !req.headers.authorization.startsWith('Bearer ')
    ) {
      return res.status(403).send(JSON.stringify({ status: 'Unauthorized' }));
    }

    const token = req.headers.authorization.split('Bearer ')[1];

    admin
      .auth()
      .verifyIdToken(token)
      .then((decodedToken) => {
        const uid = decodedToken.uid;
        admin
          .auth()
          .setCustomUserClaims(uid, { rol: ROLES.GUEST })
          .then(
            admin
              .auth()
              .getUser(uid)
              .then((user) => console.log(user.email, user.customClaims))
          );
      })
      .catch((error) => {
        // The token is invalid or has expired, so return an error
        return res.status(403).send(JSON.stringify({ status: 'Unauthorized' }));
      });
    res.status(200).send(JSON.stringify({ status: 'success' }));
  }
);

exports.autorizarUsuario = onRequest(
  { cors: [/firebase\.com$/, 'http://localhost:3000'] },
  (req, res) => {
    if (
      !req.headers.authorization ||
      !req.headers.authorization.startsWith('Bearer ')
    ) {
      return res.status(403).send(JSON.stringify({ status: 'Unauthorized' }));
    }
    const payload = req.body;
    if (!Array.isArray(payload)) {
      return res.status(204).send(
        JSON.stringify({
          status: "The body must be an Array with the courses id's",
        })
      );
    }

    const promises = [];
    const token = req.headers.authorization.split('Bearer ')[1];
    admin
      .auth()
      .verifyIdToken(token)
      .then((decodedToken) => {
        payload.forEach((id) => {
          const updatePromise = admin
            .firestore()
            .collection('courses')
            .doc(id)
            .update({
              allowedUsers: admin.firestore.FieldValue.arrayUnion(
                decodedToken.uid
              ),
            });
          promises.push(updatePromise);
        });
      })
      .catch((error) => {
        // The token is invalid or has expired, so return an error
        return res.status(403).send(JSON.stringify({ status: 'Unauthorized' }));
      });
    Promise.all(promises)
      .then(() => {
        res.status(200).send(JSON.stringify({ status: 'success' }));
      })
      .catch((err) => {
        return res.status(500).send(JSON.stringify({ err }));
      });
  }
);
