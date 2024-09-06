import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import cors from 'cors';
import dotenv from 'dotenv';
import postgres from 'postgres';

dotenv.config();

const app = express();
app.use(bodyParser.json());
app.use(cors());

// Directly use the provided DATABASE_URL
const sql = postgres('postgresql://postgres.pvozibxqckbvbtgixjgm:07034984914Bread@aws-0-eu-central-1.pooler.supabase.com:6543/postgres', {
    ssl: 'require', // Ensure SSL mode is enabled
    prepare: false  // Disable prepare as it's not supported for Transaction pool mode
});

// Define the correct username and hashed password
const MAIN_ADMIN_TABLE = 'mainadmins'; // Table name for main admin
const ADMINS_TABLE = 'admins'; // Table name for other admins

// Fetch video link
app.get('/video-link', async (req, res) => {
    try {
        const result = await sql`SELECT link FROM video_link LIMIT 1`;
        res.json({ videoLink: result[0] ? result[0].link : '' });
    } catch (error) {
        console.error('Error fetching video link:', error);
        res.status(500).json({ success: false, message: 'Error fetching video link' });
    }
});

// Update video link with admin authentication
app.post('/video-link', async (req, res) => {
    const { username, password, newVideoLink } = req.body;
    try {
        const result = await sql`SELECT password FROM ${sql(ADMINS_TABLE)} WHERE username = ${username}`;
        if (result.length === 0) {
            return res.status(400).json({ success: false, message: 'Admin not found' });
        }

        const hashedPassword = result[0].password;
        const isPasswordMatch = await bcrypt.compare(password, hashedPassword);

        if (!isPasswordMatch) {
            return res.status(400).json({ success: false, message: 'Incorrect password' });
        }

        await sql`INSERT INTO video_link (id, link) VALUES (1, ${newVideoLink}) ON CONFLICT (id) DO UPDATE SET link = ${newVideoLink}`;
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating video link:', error);
        res.status(500).json({ success: false, message: 'Error updating video link' });
    }
});

// Set up main admin (runs once to insert default admin if not exists)
async function setup() {
    try {
        const result = await sql`SELECT * FROM ${sql(MAIN_ADMIN_TABLE)} WHERE username = 'mainadmin'`;
        if (result.length === 0) {
            const hashedPassword = await bcrypt.hash(process.env.MAIN_ADMIN_PASSWORD, 10);
            await sql`INSERT INTO ${sql(MAIN_ADMIN_TABLE)} (username, password) VALUES ('mainadmin', ${hashedPassword})`;
            console.log('Main admin added successfully!');
        } else {
            console.log('Main admin already exists.');
        }
    } catch (error) {
        console.error('Error adding main admin:', error);
    }
}

// Add a new admin (Only main admin can add new admins)
app.post('/add-admin', async (req, res) => {
    const { mainAdminPassword, username, password } = req.body;
    try {
        const result = await sql`SELECT password FROM ${sql(MAIN_ADMIN_TABLE)} WHERE username = 'mainadmin'`;
        if (result.length === 0) {
            return res.status(400).json({ success: false, message: 'Main admin not found' });
        }

        const hashedMainAdminPassword = result[0].password;
        const isMainAdminPasswordMatch = await bcrypt.compare(mainAdminPassword, hashedMainAdminPassword);

        if (!isMainAdminPasswordMatch) {
            return res.status(400).json({ success: false, message: 'Incorrect main admin password' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await sql`INSERT INTO ${sql(ADMINS_TABLE)} (username, password) VALUES (${username}, ${hashedPassword})`;
        res.json({ success: true });
    } catch (error) {
        console.error('Error adding new admin:', error);
        res.status(500).json({ success: false, message: 'Error adding new admin' });
    }
});

// Login endpoint for main admin
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await sql`SELECT * FROM ${sql(MAIN_ADMIN_TABLE)} WHERE username = ${username}`;

        if (result.length === 0) {
            return res.status(400).json({ success: false, message: 'Invalid username' });
        }

        const hashedPassword = result[0].password;
        const isPasswordMatch = await bcrypt.compare(password, hashedPassword);

        if (!isPasswordMatch) {
            return res.status(400).json({ success: false, message: 'Incorrect password' });
        }

        res.json({ success: true, message: 'Login successful' });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ success: false, message: 'Server error during login' });
    }
});

// Initialize the server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// Call the setup function
setup().catch((err) => console.error(err));

