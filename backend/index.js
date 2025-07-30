const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

// Import routes
const usernameRoutes = require('./routes/username');
const emailRoutes = require('./routes/email');
const domainRoutes = require('./routes/domain');
const ipRoutes = require('./routes/ip');
const fileRoutes = require('./routes/file');

// Import utilities
const logger = require('./utils/logger');
const { errorHandler } = require('./utils/errorHandler');

const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/osint', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging middleware
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path} - ${req.ip}`);
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: require('./package.json').version
  });
});

// API Documentation endpoint
app.get('/', (req, res) => {
  res.json({
    name: 'OSINT Hawk API',
    version: '1.0.0',
    author: 'Abdul Rafay',
    description: 'Open-Source Intelligence gathering API',
    endpoints: {
      username: 'GET /osint/username?value=<username>',
      email: 'GET /osint/email?value=<email>',
      domain: 'GET /osint/domain?value=<domain>',
      ip: 'GET /osint/ip?value=<ip>',
      file: 'POST /osint/file (multipart/form-data)',
      health: 'GET /health'
    },
    documentation: 'https://github.com/your-username/osint-hawk'
  });
});

// API Routes
app.use('/osint/username', usernameRoutes);
app.use('/osint/email', emailRoutes);
app.use('/osint/domain', domainRoutes);
app.use('/osint/ip', ipRoutes);
app.use('/osint/file', fileRoutes);

// Serve static files from reports directory
app.use('/reports', express.static(path.join(__dirname, '../reports')));

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.originalUrl,
    availableEndpoints: [
      '/osint/username',
      '/osint/email', 
      '/osint/domain',
      '/osint/ip',
      '/osint/file',
      '/health'
    ]
  });
});

// Global error handler
app.use(errorHandler);

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received. Shutting down gracefully...');
  process.exit(0);
});

// Start server
app.listen(PORT, () => {
  logger.info(`🚀 OSINT Hawk API Server running on port ${PORT}`);
  logger.info(`📊 Health check: http://localhost:${PORT}/health`);
  logger.info(`📚 API docs: http://localhost:${PORT}/`);
  logger.info(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
