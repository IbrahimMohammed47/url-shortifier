const express = require('express');
const app = express();
const bodyParser = require('body-parser')
app.use(bodyParser.json())
const core = require('../services/core');

app.post('/urls', async function (req, res) {
  const { url, ttlInDays } = req.body;

  if (!await core.isValidTTL(ttlInDays))
    return res.status(400).send("invalid expiration");

  if (!await core.isValidURL(url))
    return res.status(400).send("invalid url");

  if (!await core.isSafeURL(url))
    return res.status(400).send("malicious url");

  const hash = core.hashURL(url);

  if (!await core.isHashAvailable(hash))
    return res.status(400).send("url already shortened");

  core.saveShortURL(hash, url, ttlInDays * 24 * 60 * 60)

  return res.send(hash);
});

app.get('/urls/:hash', async function (req, res) {
  const hash = req.params.hash;
  let data = await core.getSURLInfo(hash);
  if (!data)
    return res.status(400).send("surl not found or expired");
  let exp = await core.getExpiryDate(hash);
  data.ttlInDays = exp;
  res.send(data);
});

app.get('/:hash', async function (req, res) {
  const hash = req.params.hash;
  const url = await core.getOriginalURL(hash);
  if (!url) {
    return res.status(400).send("surl not found or expired");
  }
  res.redirect(url);
  core.incrementClickCount(hash)
});

module.exports = app;
