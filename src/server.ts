import express from 'express';
import compression from 'compression';
import cors from 'cors';
import path from 'path';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(compression());
app.use(cors());

// Serve static files from the workspace root so demos remain accessible
const staticDir = path.resolve(__dirname, '..');
app.use(express.static(staticDir));

// Root route serves the modern index.html
app.get('/', (_req, res) => {
  res.sendFile(path.join(staticDir, 'index.html'));
});

// Fallback: serve 404 for unknown routes that aren't static
app.use((_req, res) => {
  res.status(404).send('404 Not Found');
});

app.listen(PORT, () => {
  console.log(`ImprobIA server running at http://localhost:${PORT}`);
});