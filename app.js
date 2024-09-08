const express = require('express');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/auth');
const credentialsRoutes = require('./routes/credentials');
const usersRoutes = require('./routes/user');
const ip_address = require('./routes/ip_address');

const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cors());

app.use('/api/auth', authRoutes);
app.use('/api/credentials', credentialsRoutes);
app.use('/api/user',usersRoutes)
app.use('/api/ip',ip_address)

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
