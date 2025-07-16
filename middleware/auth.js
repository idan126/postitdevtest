const { ObjectId } = require('mongodb');
const { getSession } = require('../utils/sessionStore');

const COOKIE_NAME = 'sid';

async function authMiddleware(req, res, next) {
    const sid = req.cookies[COOKIE_NAME];
    const session = getSession(sid);
    if (!session) return res.status(401).json({ error: 'Not authenticated' });

    const usersCollection = req.app.locals.usersCollection;
    const user = await usersCollection.findOne({ _id: new ObjectId(session.userId) }, { projection: { hashedPassword: 0 } });

    if (!user) return res.status(401).json({ error: 'User not found' });

    req.user = user;
    req.userId = session.userId;
    next();
}

module.exports = authMiddleware;