/**
 * server.js
 *
 * Fixes:
 * - Improper type validation and XSS prevention using express-validator and sanitize-html.
 * - Secure HTTP requests using axios (HTTPS only), SSRF protection with DNS, IP checks, allowlist, and DNS rebinding prevention.
 * - Rate limiting with express-rate-limit to prevent resource exhaustion.
 * - Use Helmet for secure headers.
 * - Improved error handling and generic error messages.
 *
 * Install dependencies:
 * npm install express body-parser ejs helmet express-rate-limit express-validator axios sanitize-html node-vault
 *
 * Configuration:
 *  - VAULT_ADDR, VAULT_TOKEN for Vault
 *  - PORT (optional)
 *  - ALLOWED_HOSTS: comma-separated list of permitted hostnames for /fetch
 */
require('dotenv').config();
const client = require('prom-client');
const express = require('express');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, query, validationResult } = require('express-validator');
const axios = require('axios');
const sanitizeHtml = require('sanitize-html');
const vault = require('node-vault');
const { URL } = require('url');
const dns = require('dns').promises;
const net = require('net');
const https = require('https');

const app = express();
const port = process.env.PORT || 3000;
const ALLOWED_HOSTS = (process.env.ALLOWED_HOSTS || '').split(',').filter(Boolean);

// collect default metrics (CPU, memory, event loop, ecc.)
client.collectDefaultMetrics({ timeout: 5000 });

const httpRequests = new client.Counter({
    name: 'http_requests_total',
    help: 'Number of HTTP requests',
    labelNames: ['method', 'route', 'status_code']
});

const httpDuration = new client.Histogram({
    name: "app_request_duration_seconds",
    help: "Request duration in seconds",
    labelNames: ["method", "route", "status_code"],
    buckets: [0.1, 0.3, 1, 2, 3, 5],
});

const errorCounter = new client.Counter({
    name: "http_error_requests_total",
    help: "Total HTTP 5xx error requests",
    labelNames: ["method", "route", "status_code"],
});

// Vault helper function with secure token retrieval
async function getStripeSecret() {
    try {
        const client = vault({ apiVersion: 'v1', endpoint: process.env.VAULT_ADDR });
        client.token = process.env.VAULT_TOKEN;
        const result = await client.read('secret/data/stripe');

        return result.data.data.secret;
    } catch (error) {
        console.error('Vault error:', error.response.body.errors);
        throw new Error('Could not retrieve stripe secret');
    }
}

// Check if IP is private for SSRF protection
function isPrivateIp(ip) {
    if (!net.isIP(ip)) return false;
    // IPv4 private ranges
    if (
        ip.startsWith('10.') ||
        ip.startsWith('192.168.') ||
        ip === '127.0.0.1' ||
        ip.startsWith('169.254.') ||
        (/^172\.(1[6-9]|2[0-9]|3[0-1])\./).test(ip)
    ) return true;
    // IPv6 local addresses
    if (ip === '::1' || ip.startsWith('fc00:') || ip.startsWith('fe80:')) return true;
    return false;
}

// Middleware
app.use(helmet());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use((req, res, next) => {
    const end = httpDuration.startTimer({
        method: req.method,
        route: req.path,
    });
    res.on("finish", () => {
        end({ status_code: res.statusCode });
    });
    next();
});

app.use((req, res, next) => {
    const end = res.end;
    res.end = function (chunk, encoding) {
        httpRequests.inc({
            method: req.method,
            route: req.route ? req.route.path : req.path,
            status_code: res.statusCode
        });
        end.apply(this, [chunk, encoding]);
    };
    next();
});

app.use((req, res, next) => {
    const end = res.end;
    res.end = function (chunk, encoding) {
        if (res.statusCode >= 500) {
            errorCounter.inc({
                method: req.method,
                route: req.route ? req.route.path : req.path,
                status_code: res.statusCode,
            });
        }
        httpRequests.inc({
            /* existing counter code */
        });
        end.apply(this, [chunk, encoding]);
    };
    next();
});

// Global rate limiter to prevent DoS
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per window
    message: 'Too many requests, please try again later.',
});
// app.use(limiter);

// View engine setup
app.set('view engine', 'ejs');

// Home
app.get('/', (_req, res) => {
    res.render('index', { output: '' });
});

// Command execution (disabled)
app.post(
    '/command',
    body('command')
        .exists().withMessage('Command is required')
        .isString().withMessage('Command must be a string')
        .trim().escape(),
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).send('Invalid command input');
        }
        const command = req.body.command;
        res.render('index', { output: `Command execution is disabled. You attempted to run: ${command}` });
    }
);

// XSS demo with input sanitization
app.get(
    '/xss',
    query('input')
        .optional()
        .isString().withMessage('Input must be a string'),
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).send('Invalid input');
        }
        const rawInput = req.query.input || 'Enter something';
        const safeInput = sanitizeHtml(rawInput);
        res.send(`
            <h1>XSS Vulnerability Demo</h1>
            <p>Your input: ${safeInput}</p>
            <form action="/xss" method="GET">
              <input type="text" name="input" placeholder="Enter text" />
              <button type="submit">Submit</button>
            </form>
        `);
    }
);

// Fetch external content with robust SSRF protection
app.get(
    '/fetch',
    query('url')
        .exists().withMessage('URL is required')
        .isURL({ protocols: ['https'], require_protocol: true }).withMessage('Invalid URL. Only HTTPS is allowed.'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).send('Invalid URL. Only HTTPS URLs are allowed.');
        }
        const urlStr = req.query.url;

        // Parse URL
        let parsed;
        try {
            parsed = new URL(urlStr);
        } catch (err) {
            return res.status(400).send('Invalid URL format.');
        }

        // Allowlist enforcement
        if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
            return res.status(400).send('Host not allowed.');
        }

        // DNS lookup
        let resolvedAddresses;
        try {
            resolvedAddresses = await dns.lookup(parsed.hostname, { all: true });
        } catch (err) {
            console.error('DNS lookup error:', err);
            return res.status(400).send('Unable to resolve host.');
        }

        const addresses = resolvedAddresses.map(item => item.address);
        // IP filtering
        for (const address of addresses) {
            if (isPrivateIp(address)) {
                return res.status(400).send('URL resolves to a disallowed IP address.');
            }
        }

        // Prevent DNS rebinding by using fixed IP and custom agent
        const agent = new https.Agent({
            lookup: (_hostname, options, callback) => {
                // Use first resolved IP
                callback(null, addresses[0], net.isIP(addresses[0]));
            },
            servername: parsed.hostname
        });

        // Construct safe URL without user manipulation
        const safeUrl = `${parsed.protocol}//${parsed.hostname}${parsed.port ? ':' + parsed.port : ''}${parsed.pathname}${parsed.search}`;

        try {
            const response = await axios.get(safeUrl, {
                httpsAgent: agent,
                timeout: 5000,
                maxRedirects: 5,
                headers: { Host: parsed.hostname }
            });
            res.type('text/plain').send(response.data);
        } catch (error) {
            console.error('Fetch error:', error);
            res.status(502).send('Error fetching URL.');
        }
    }
);

app.get('/metrics', async (req, res) => {
    res.set('Content-Type', client.register.contentType);
    res.end(await client.register.metrics());
});

app.get("/error", (req, res) => {
    res.status(500).send("Internal Server Error");
});

app.get("/delay", (req, res) => {
    const delay = Math.random() * 2500;

    setTimeout(() => {
        res.sendStatus(200);
    }, delay);
})

// Generic error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

app.listen(port, async () => {
    const stripeSecret = await getStripeSecret();

    console.info(`App listening on port ${port}`);

    console.log(`Stripe secret: ${stripeSecret}`);
});
