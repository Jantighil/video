import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import cors from 'cors';
import helmet from 'helmet';
import path from 'path';
import pg from 'pg'; 
import { fileURLToPath } from 'url'; 
import { createClient } from '@supabase/supabase-js'; 
import dotenv from 'dotenv';

dotenv.config(); 

const { Pool } = pg; 
const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Configure CORS
app.use(cors({
  origin: 'https://video-nu-ecru.vercel.app', // Allow requests from this domain
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type'],
}));

app.use(bodyParser.json());
app.use(helmet());
app.use(express.static(path.join(__dirname, 'public')));

async function getMainAdminCredentials() {
  try {
    const result = await pool.query('SELECT username, password FROM mainadmin LIMIT 1');
    return result.rows.length > 0 ? result.rows[0] : null;
  } catch (error) {
    console.error("Error fetching main admin credentials:", error);
    throw new Error("Could not fetch admin credentials");
  }
}

app.get('/video-link', async (req, res) => {
  try {
    const result = await pool.query('SELECT link FROM video_link LIMIT 1');
    res.json({ videoLink: result.rows[0] ? result.rows[0].link : '' });
  } catch (error) {
    console.error('Error fetching video link:', error);
    res.status(500).json({ success: false, message: 'Error fetching video link' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const mainAdmin = await getMainAdminCredentials();

    if (!mainAdmin) {
      return res.status(500).json({ success: false, message: 'Main admin credentials not found' });
    }

    const isPasswordMatch = await bcrypt.compare(password, mainAdmin.password);
    if (username === mainAdmin.username && isPasswordMatch) {
      return res.json({ success: true, message: 'Login successful' });
    } else {
      return res.status(400).json({ success: false, message: 'Invalid username or password' });
    }
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ success: false, message: 'Server error during login' });
  }
});

app.post('/video-link', async (req, res) => {
  const { username, password, newVideoLink } = req.body;

  try {
    const mainAdmin = await getMainAdminCredentials();

    if (!mainAdmin) {
      return res.status(500).json({ success: false, message: 'Main admin credentials not found' });
    }

    const isPasswordMatch = await bcrypt.compare(password, mainAdmin.password);

    if (username === mainAdmin.username && isPasswordMatch) {
      await pool.query('INSERT INTO video_link (id, link) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET link = $2', [1, newVideoLink]);
      res.json({ success: true, message: 'Video link updated' });
    } else {
      res.status(400).json({ success: false, message: 'Unauthorized' });
    }
  } catch (error) {
    console.error('Error updating video link:', error);
    res.status(500).json({ success: false, message: 'Error updating video link' });
  }
});

app.delete('/video-link', async (req, res) => {
  const { username, password } = req.body;

  try {
    const mainAdmin = await getMainAdminCredentials();

    if (!mainAdmin) {
      return res.status(500).json({ success: false, message: 'Main admin credentials not found' });
    }

    const isPasswordMatch = await bcrypt.compare(password, mainAdmin.password);

    if (username === mainAdmin.username && isPasswordMatch) {
      await pool.query('DELETE FROM video_link WHERE id = $1', [1]);
      res.json({ success: true, message: 'Video link deleted' });
    } else {
      res.status(400).json({ success: false, message: 'Unauthorized' });
    }
  } catch (error) {
    console.error('Error deleting video link:', error);
    res.status(500).json({ success: false, message: 'Error deleting video link' });
  }
});

app.post('/add-admin', async (req, res) => {
  const { mainAdminPassword, username, password } = req.body;

  try {
    const mainAdmin = await getMainAdminCredentials();

    if (!mainAdmin) {
      return res.status(500).json({ success: false, message: 'Main admin credentials not found' });
    }

    const isPasswordMatch = await bcrypt.compare(mainAdminPassword, mainAdmin.password);

    if (isPasswordMatch) {
      const hashedPassword = await bcrypt.hash(password, 10);
      await pool.query('INSERT INTO admins (username, password) VALUES ($1, $2)', [username, hashedPassword]);
      res.json({ success: true, message: 'New admin added' });
    } else {
      res.status(400).json({ success: false, message: 'Main admin authentication failed' });
    }
  } catch (error) {
    console.error('Error adding new admin:', error);
    res.status(500).json({ success: false, message: 'Error adding new admin' });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

supabase
  .channel('video_link')
  .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'video_link' }, handleInserts)
  .subscribe();

function handleInserts(payload) {
  console.log('Change received!', payload);
}
