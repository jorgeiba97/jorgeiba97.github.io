import express from 'express';
import compression from 'compression';
import cors from 'cors';
import path from 'path';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { z } from 'zod';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security Headers (Helmet) with customized CSP for ImprobIA portfolio and demos
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://cdn.tailwindcss.com",
          "https://unpkg.com"
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com",
          "https://unpkg.com",
          "https://cdnjs.cloudflare.com"
        ],
        imgSrc: [
          "'self'",
          "data:",
          "https://placehold.co",
          "https://tile.openstreetmap.org",
          "https://*.openstreetmap.org",
          "https://unpkg.com"
        ],
        fontSrc: [
          "'self'",
          "https://fonts.gstatic.com",
          "https://cdnjs.cloudflare.com"
        ],
        frameSrc: [
          "'self'",
          "https://www.google.com"
        ],
        connectSrc: ["'self'"]
      }
    },
    // X-Content-Type-Options: nosniff
    noSniff: true,
    // X-Frame-Options: DENY (clickjacking protection)
    frameguard: {
      action: 'deny'
    }
  })
);

// Global Rate Limiter: Prevent DoS on static assets and overall server
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 150, // limit each IP to 150 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas peticiones desde esta IP. Por favor, inténtelo de nuevo en 15 minutos.' }
});
app.use(globalLimiter);

// Parse JSON request bodies
app.use(express.json());

app.use(compression());
app.use(cors());

// Serve static files from the workspace root so demos remain accessible
const staticDir = path.resolve(__dirname, '..');
app.use(express.static(staticDir));

// Root route serves the modern index.html
app.get('/', (_req, res) => {
  res.sendFile(path.join(staticDir, 'index.html'));
});

// Form Submission Rate Limiter: Strict limit to prevent form abuse and spam
const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // limit each IP to 3 contact requests per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Ha enviado demasiados mensajes. Por favor, inténtelo de nuevo en una hora.' }
});

// Zod Schema for validation and sanitization
const contactSchema = z.object({
  nombre: z.string()
    .min(2, { message: 'El nombre debe tener al menos 2 caracteres.' })
    .max(100, { message: 'El nombre no puede exceder los 100 caracteres.' })
    .transform(val => val.replace(/<[^>]*>/g, '').trim()), // Simple HTML tag sanitization
  phone: z.string()
    .min(5, { message: 'El teléfono debe tener al menos 5 dígitos.' })
    .max(20, { message: 'El teléfono no puede exceder los 20 dígitos.' })
    .regex(/^[\d\s+\-()]*$/, { message: 'El teléfono solo puede contener números, espacios, +, - o paréntesis.' })
    .trim(),
  email: z.string()
    .email({ message: 'Debe ingresar un correo electrónico válido.' })
    .trim(),
  mensaje: z.string()
    .min(5, { message: 'El mensaje debe tener al menos 5 caracteres.' })
    .max(2000, { message: 'El mensaje no puede exceder los 2000 caracteres.' })
    .transform(val => val.replace(/<[^>]*>/g, '').trim()) // Simple HTML tag sanitization
});

// Secured Intermediate Formspree Proxy Route
app.post('/api/contact', contactLimiter, async (req, res) => {
  try {
    // Validate and sanitize input parameters using Zod
    const validationResult = contactSchema.safeParse(req.body);
    if (!validationResult.success) {
      const errorMessages = validationResult.error.issues.map(err => err.message);
      return res.status(400).json({ error: errorMessages.join(' ') });
    }

    const { nombre, phone, email, mensaje } = validationResult.data;

    // Retrieve hidden Formspree ID from environment variable
    const formId = process.env.FORMSPREE_FORM_ID;
    if (!formId || formId === 'your_formspree_id_here') {
      console.error('Configuration Error: FORMSPREE_FORM_ID is missing or not set.');
      return res.status(500).json({ error: 'Configuración del servidor incompleta. Por favor, inténtelo más tarde.' });
    }

    // Forward payload securely to Formspree from the backend
    const response = await fetch(`https://formspree.io/f/${formId}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({ nombre, phone, email, mensaje })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`Formspree forwarding failed: Status ${response.status} - ${errorText}`);
      return res.status(502).json({ error: 'No se pudo procesar el envío con el proveedor de correo. Intente más tarde.' });
    }

    return res.status(200).json({ success: true, message: '¡Mensaje enviado con éxito!' });
  } catch (error: any) {
    // Clean logs and zero leak of secrets
    console.error('Server error handling contact submission:', error?.message || error);
    return res.status(500).json({ error: 'Ocurrió un error interno en el servidor al procesar el mensaje.' });
  }
});

// Fallback: serve 404 for unknown routes that aren't static
app.use((_req, res) => {
  res.status(404).send('404 Not Found');
});

app.listen(PORT, () => {
  console.log(`ImprobIA secure server running at http://localhost:${PORT}`);
});