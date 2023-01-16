const app = require('./app');
const http = require('http');
const { connectToMongoDB } = require('./services/connect.mongo');
require('dotenv').config();

const PORT = process.env.PORT || 5000;
const server = http.createServer(app);

async function startServer() {
  try {
    await connectToMongoDB();
    server.listen(PORT, () => {
      console.log(`The server is listening on port ${PORT}...`);
    });
  } catch (error) {
    console.log(error);
  }
}

startServer();