const validator = require("validator");
const fetch = require("node-fetch");
const redisClient = require('../config/redisClient');
const md5 = require('md5');

module.exports.hashURL = function (url) {
  let hash = md5(url + process.env.SALT); // salted
  hash = hash.split('');
  hash = hash.filter((v, idx) => (idx % 4 == 0)); // taking 8 characters out of 32 
  return hash.join('');
}

module.exports.getSURLInfo = async function (hash) {
  const key = 'surl:' + hash;
  const info = await redisClient.hgetallAsync(key);
  return info;
}

module.exports.isValidTTL = async function (ttl) {
  return (typeof ttl === 'number'
    && ttl <= 90 // 3 months max
    && ttl >= 1) // 1 day min
}

module.exports.isValidURL = async function (url) {
  return await validator.isURL(url);
}

module.exports.isSafeURL = async function (url) {
  const rawResponse = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.G_SAFE_BROWSNING_API_KEY}`, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      client: {
        clientId: "ibrahim_url_shortner_test",
        clientVersion: "1.0.1"
      },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "THREAT_TYPE_UNSPECIFIED", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ "url": url }]
      }
    })
  });
  const content = await rawResponse.json();
  if (Object.keys(content).length === 0 && content.constructor === Object) {
    return true;
  }
  return false;
}

module.exports.saveShortURL = async function (hash, url, ttl) {
  const key = 'surl:' + hash;
  await redisClient.hmsetAsync(key, 'url', url, 'count', 0);
  await redisClient.expireAsync(key, ttl)
}

module.exports.isHashAvailable = async function (hash) {
  const exists = await redisClient.existsAsync('surl:' + hash);
  return (!exists)
}

module.exports.getExpiryDate = async function (hash) {
  const key = 'surl:' + hash;
  const ttlInSeconds = await redisClient.ttlAsync(key);
  const ttlInDays = ttlInSeconds / 60 / 60 / 24;
  return ttlInDays.toPrecision(3);
}

module.exports.getOriginalURL = async function (hash) {
  const key = 'surl:' + hash;
  const url = await redisClient.hgetAsync(key, 'url');
  return url;
}

module.exports.incrementClickCount = function (hash) {
  const key = 'surl:' + hash;
  redisClient.hincrbyAsync(key, 'count', 1);
}
