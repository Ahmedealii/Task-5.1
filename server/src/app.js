import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import mongoSanitize from 'express-mongo-sanitize';
import authRoutes from './routes/auth.js';
import reviewRoutes from './routes/reviews.js';
import userRoutes from './routes/users.js';
import instructorRoutes from './routes/instructors.js';

const app = express();

// 1. Core middleware & logging
app.use(morgan('dev'));
app.use(cors({ origin: 'http://localhost:5175', credentials: false }));

// 2. Parse body (use express built-in parsers - do NOT combine with bodyParser)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 3. Sanitize inputs against NoSQL injection (runs AFTER body is parsed)
app.use(
  mongoSanitize({
    onSanitize: ({ key }) => {
      console.warn(`[mongoSanitize] Stripped potentially dangerous query operator in: ${key}`);
    },
  })
);

// 4. Health check
app.get('/api/health', (req, res) => res.json({ ok: true }));

// 5. Routes
app.use('/api/auth', authRoutes);
app.use('/api/reviews', reviewRoutes);
app.use('/api/users', userRoutes);
app.use('/api/instructors', instructorRoutes);

// 6. 404 handler
app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

// 7. Central error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;