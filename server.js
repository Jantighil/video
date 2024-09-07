import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import cors from 'cors';
import dotenv from 'dotenv';
import pkg from 'pg'; // Correct import for pg with ESM
import helmet from 'helmet';
import path from 'path';

dotenv.config();  // Loads environment variables from .env file

const { Pool } = pkg; // Correctly import Pool from pg

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(helmet());
app.use(express.static(path.resolve('public')));

// PostgreSQL Pool using Supabase connection string
const pool = new Pool({
  connectionString: process.env.SUPABASE_DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Test Database Connection
async function testDatabaseConnection() {
    try {
        const result = await pool.query('SELECT NOW()');
        console.log('Database connection test:', result.rows[0]);
    } catch (error) {
        console.error('Database connection test failed:', error);
    }
}

testDatabaseConnection(); // Call to test connection

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
        res.status(500).json({ success: false, message: 'Error fetching video link', error: error.message });
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
        console.error('Error during login:', error); // Log detailed error
        res.status(500).json({ success: false, message: 'Server error during login', error: error.message });
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
            // Insert or update the video link
            await pool.query(`INSERT INTO video_link (id, link) VALUES (1, $1) 
                ON CONFLICT (id) DO UPDATE SET link = $1`, [newVideoLink]);
            res.json({ success: true, message: 'Video link updated' });
        } else {
            res.status(400).json({ success: false, message: 'Unauthorized' });
        }
    } catch (error) {
        console.error('Error updating video link:', error);
        res.status(500).json({ success: false, message: 'Error updating video link', error: error.message });
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
            await pool.query('DELETE FROM video_link WHERE id = 1');
            res.json({ success: true, message: 'Video link deleted' });
        } else {
            res.status(400).json({ success: false, message: 'Unauthorized' });
        }
    } catch (error) {
        console.error('Error deleting video link:', error);
        res.status(500).json({ success: false, message: 'Error deleting video link', error: error.message });
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
            // Hash the new admin password and insert into database
            const hashedPassword = await bcrypt.hash(password, 10);
            await pool.query('INSERT INTO admins (username, password) VALUES ($1, $2)', [username, hashedPassword]);
            res.json({ success: true, message: 'New admin added' });
        } else {
            res.status(400).json({ success: false, message: 'Main admin authentication failed' });
        }
    } catch (error) {
        console.error('Error adding new admin:', error);
        res.status(500).json({ success: false, message: 'Error adding new admin', error: error.message });
    }
});

// Start the server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
