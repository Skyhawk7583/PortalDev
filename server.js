const express = require("express");
const app = express();
const PORT = process.env.PORT || 5000;

app.get('/', (req, res) => res.send('Wello Horld?'));




app.listen(PORT, () => console.log(`Server Started on port ${PORT}`));