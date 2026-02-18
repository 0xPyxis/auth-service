require('dotenv').config();         // loads environment variables from a .env file.

const express = require('express');     // Express wraps Node’s HTTP module and makes routing easy.

const app = express();              // creates the main server instance

app.use(express.json());            // This is middleware. It parses incoming JSON bodies and puts them inside: req.body

app.get('/health',(req,res)=>{      // This is a health check endpoint. In prod, balancers etc ping this to check health of our server.
    res.status(200).json({status: 'OK'});
});

const PORT = process.env.PORT || 5000;  // if port is specified in env file use it, else use default one as 5000

app.listen(PORT, ()=>{
    console.log(`Server running on port ${PORT}`);
});