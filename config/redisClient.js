const redis = require('redis')
const bluebird = require("bluebird");
bluebird.promisifyAll(redis);

const client = redis.createClient({
  port: 6379,
  host: process.env.REDIS_HOST
});

client.on("connect", function () {
  console.log("connected to Redis...");
});

module.exports = client