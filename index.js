const { createApp } = require('./dist');
const app = createApp();

app.get('/api', (req, res) => {
  res.send('Hello from AryaCore!');
});

app.post('/api', (req, res) => {
  const data = req.body;
 res.send(data.data);
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});