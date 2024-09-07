import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import cors from 'cors';
import helmet from 'helmet';
import path from 'path';
import pg from 'pg'; // Import the default export from CommonJS module
import { fileURLToPath } from 'url'; // Import for defining __dirname in ES modules
import { createClient } from '@supabase/supabase-js'; // Import Supabase client

const { Pool } = pg; // Destructure Pool from the default export
import dotenv from 'dotenv';

dotenv.config(); // Load environment variables from .env file

const app = express();

// Define __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Supabase client setup
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// PostgreSQL Pool using Supabase connection string
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Use environment variable for security
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(cors());
app.use(bodyParser.json());
app.use(helmet());
app.use(express.static(path.join(__dirname, 'public')));

// Fetch the admin credentials from Supabase's mainadmin table
async function getMainAdminCredentials() {
  try {
    const result = await pool.query('SELECT username, password FROM mainadmin LIMIT 1');
    return result.rows.length > 0 ? result.rows[0] : null;
  } catch (error) {
    console.error("Error fetching main admin credentials:", error);
    throw new Error("Could not fetch admin credentials");
  }
}

// Fetch the video link from Supabase
app.get('/video-link', async (req, res) => {
  try {
    const result = await pool.query('SELECT link FROM video_link LIMIT 1');
    res.json({ videoLink: result.rows[0] ? result.rows[0].link : '' });
  } catch (error) {
    console.error('Error fetching video link:', error);
    res.status(500).json({ success: false, message: 'Error fetching video link' });
  }
});

// Admin authentication for login
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

// Update video link with admin authentication
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

// Delete video link with admin authentication
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

// Add a new admin (Only main admin can add new admins)
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

// Start the server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Real-time subscription to Supabase for new records in the 'video_link' table
supabase
  .channel('video_link')
  .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'video_link' }, handleInserts)
  .subscribe();

// Handle insert changes from Supabase
function handleInserts(payload) {
  console.log('Change received!', payload);
  // Handle the payload as needed
}
