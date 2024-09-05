import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import cors from 'cors';
import dotenv from 'dotenv';
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';

dotenv.config();

const app = express();
const connectionString = process.env.DATABASE_URL;

// Initialize PostgreSQL client and Drizzle ORM
const client = postgres(connectionString, { prepare: false });
const db = drizzle(client);

app.use(bodyParser.json());
app.use(cors());

// Fetch video link
app.get('/video-link', async (req, res) => {
    try {
        const result = await db.select('link').from('video_link').limit(1);
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
        const result = await db.select('password').from('admins').where('username', username);
        if (result.length === 0) {
            return res.status(400).json({ success: false, message: 'Admin not found' });
        }

        const hashedPassword = result[0].password;
        const isPasswordMatch = await bcrypt.compare(password, hashedPassword);

        if (!isPasswordMatch) {
            return res.status(400).json({ success: false, message: 'Incorrect password' });
        }

        await db.insert('video_link').values({ id: 1, link: newVideoLink }).onConflict('id').merge();
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating video link:', error);
        res.status(500).json({ success: false, message: 'Error updating video link' });
    }
});

// Set up main admin (runs once to insert default admin if not exists)
async function setup() {
    try {
        const result = await db.select('*').from('admins').where('username', 'mainadmin');
        if (result.length === 0) {
            const hashedPassword = await bcrypt.hash(process.env.MAIN_ADMIN_PASSWORD, 10);
            await db.insert('admins').values({ username: 'mainadmin', password: hashedPassword });
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
        const result = await db.select('password').from('admins').where('username', 'mainadmin');
        if (result.length === 0) {
            return res.status(400).json({ success: false, message: 'Main admin not found' });
        }

        const hashedMainAdminPassword = result[0].password;
        const isMainAdminPasswordMatch = await bcrypt.compare(mainAdminPassword, hashedMainAdminPassword);

        if (!isMainAdminPasswordMatch) {
            return res.status(400).json({ success: false, message: 'Incorrect main admin password' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.insert('admins').values({ username, password: hashedPassword });
        res.json({ success: true });
    } catch (error) {
        console.error('Error adding new admin:', error);
        res.status(500).json({ success: false, message: 'Error adding new admin' });
    }
});

// Initialize the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// Call the setup function
setup().catch((err) => console.error(err));
