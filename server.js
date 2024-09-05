const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const cors = require('cors');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const app = express();

// Use Supabase connection string for the database
const pool = new Pool({
  connectionString: process.env.SUPABASE_DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

app.use(bodyParser.json());
app.use(cors());

// Fetch video link
app.get('/video-link', async (req, res) => {
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT link FROM video_link LIMIT 1');
    res.json({ videoLink: result.rows[0] ? result.rows[0].link : '' });
  } catch (error) {
    console.error('Error fetching video link:', error);
    res.status(500).json({ success: false, message: 'Error fetching video link' });
  } finally {
    client.release();
  }
});

// Update video link with admin authentication
app.post('/video-link', async (req, res) => {
  const { username, password, newVideoLink } = req.body;
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT password FROM admins WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'Admin not found' });
    }

    const hashedPassword = result.rows[0].password;
    const isPasswordMatch = await bcrypt.compare(password, hashedPassword);

    if (!isPasswordMatch) {
      return res.status(400).json({ success: false, message: 'Incorrect password' });
    }

    await client.query(
      'INSERT INTO video_link (id, link) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET link = $1',
      [newVideoLink]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating video link:', error);
    res.status(500).json({ success: false, message: 'Error updating video link' });
  } finally {
    client.release();
  }
});

// Set up main admin (runs once to insert default admin if not exists)
async function setup() {
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM admins WHERE username = $1', ['mainadmin']);
    if (result.rows.length === 0) {
      const hashedPassword = await bcrypt.hash(process.env.MAIN_ADMIN_PASSWORD, 10);
      await client.query('INSERT INTO admins (username, password) VALUES ($1, $2)', ['mainadmin', hashedPassword]);
      console.log('Main admin added successfully!');
    } else {
      console.log('Main admin already exists.');
    }
  } catch (error) {
    console.error('Error adding main admin:', error);
  } finally {
    client.release();
  }
}

// Add a new admin (Only main admin can add new admins)
app.post('/add-admin', async (req, res) => {
  const { mainAdminPassword, username, password } = req.body;
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT password FROM admins WHERE username = $1', ['mainadmin']);
    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'Main admin not found' });
    }

    const hashedMainAdminPassword = result.rows[0].password;
    const isMainAdminPasswordMatch = await bcrypt.compare(mainAdminPassword, hashedMainAdminPassword);

    if (!isMainAdminPasswordMatch) {
      return res.status(400).json({ success: false, message: 'Incorrect main admin password' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await client.query('INSERT INTO admins (username, password) VALUES ($1, $2)', [username, hashedPassword]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error adding new admin:', error);
    res.status(500).json({ success: false, message: 'Error adding new admin' });
  } finally {
    client.release();
  }
});

// Initialize the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Call the setup function
setup().catch((err) => console.error(err));
