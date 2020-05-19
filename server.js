require('dotenv').config();
const app = require('./controllers/url_controller');
const port = process.env.PORT;


app.listen(port, function () {
  console.log(`listening at http://localhost:${port}`)
});

