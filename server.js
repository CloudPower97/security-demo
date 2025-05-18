require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const { exec } = require('child_process');
const http = require('http'); // Required for SSRF demo
const path = require('path');
const app = express();
const port = 3000;

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;

app.use(bodyParser.urlencoded({ extended: true }));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Insecure practice: Verbose error messages
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke! Details: ' + err.message); // Reveals error details
});

app.get('/', (req, res) => {
    res.render('index.ejs', { output: '' });
});

// Vulnerable to Command Injection
app.post('/command', (req, res) => {
    const command = req.body.command;
    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error(`exec error: ${error}`);
            return res.render('index', { output: `Error: ${error.message}` });
        }
        res.render('index', { output: `Output:\n${stdout}\nStderr:\n${stderr}` });
    });
});

// Vulnerable to XSS
app.get('/xss', (req, res) => {
    const input = req.query.input || 'Enter something';
    res.send(`
    <h1>XSS Vulnerability Demo</h1>
    <p>Your input: ${input}</p>
    <form action="/xss" method="GET">
      <input type="text" name="input" placeholder="Enter text">
      <button type="submit">Submit</button>
    </form>
  `);
});

// Vulnerable to SSRF
app.get('/fetch', (req, res) => {
    const url = req.query.url;
    if (!url) {
        return res.send("Please provide a URL to fetch.");
    }

    // Insecure: Fetching content from a user-provided URL without validation
    http.get(url, (response) => {
        let data = '';
        response.on('data', (chunk) => {
            data += chunk;
        });
        response.on('end', () => {
            res.send(`Content from ${url}:\n${data}`);
        });
    }).on('error', (err) => {
        res.send(`Error fetching URL: ${err.message}`);
    });
});


// Insecure practice: No security headers (like helmet)
app.listen(port, () => {
    console.log(`App listening at http://localhost:${port}`);
    console.log(STRIPE_SECRET_KEY);
});
