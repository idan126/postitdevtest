const { v4: uuidv4 } = require('uuid');

const SESSION_STORE = {};
const SESSION_DURATION = 15 * 60 * 1000;

function createSession(userId) {
    const sid = uuidv4();
    SESSION_STORE[sid] = { userId, expires: Date.now() + SESSION_DURATION };
    return sid;
}

function getSession(sid) {
    const session = SESSION_STORE[sid];
    if (!session || session.expires < Date.now()) {
        delete SESSION_STORE[sid];
        return null;
    }
    return session;
}

module.exports = {
    createSession,
    getSession,
    SESSION_DURATION,
};