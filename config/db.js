const { MongoClient } = require('mongodb');

const client = new MongoClient(process.env.MONGO_URI);
let usersCollection;

async function connectToMongo(app, port) {
    try {
        await client.connect();
        usersCollection = client.db().collection('users');
        app.locals.usersCollection = usersCollection;
        console.log('✅ Connected to MongoDB');

        app.listen(port, () =>
            console.log(`🚀 Server ready at http://localhost:${port}`)
        );
    } catch (err) {
        console.error('❌ MongoDB connection failed:', err);
        process.exit(1);
    }
}

module.exports = connectToMongo;