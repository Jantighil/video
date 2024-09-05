import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import cors from 'cors';
import dotenv from 'dotenv';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';

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
        const result = await db.sql`SELECT link FROM video_link LIMIT 1`;
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
        const [admin] = await db.sql`SELECT password FROM admins WHERE username = ${username}`;
        if (!admin) {
            return res.status(400).json({ success: false, message: 'Admin not found' });
        }

        const isPasswordMatch = await bcrypt.compare(password, admin.password);
        if (!isPasswordMatch) {
            return res.status(400).json({ success: false, message: 'Incorrect password' });
        }

        await db.sql`
            INSERT INTO video_link (id, link)
            VALUES (1, ${newVideoLink})
            ON CONFLICT (id) DO UPDATE
            SET link = ${newVideoLink}
        `;
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating video link:', error);
        res.status(500).json({ success: false, message: 'Error updating video link' });
    }
});

// Set up main admin (runs once to insert default admin if not exists)
async function setup() {
    try {
        const [admin] = await db.sql`SELECT * FROM admins WHERE username = ${'mainadmin'}`;
        if (!admin) {
            const hashedPassword = await bcrypt.hash(process.env.MAIN_ADMIN_PASSWORD, 10);
            await db.sql`INSERT INTO admins (username, password) VALUES (${ 'mainadmin' }, ${hashedPassword})`;
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
        const [mainAdmin] = await db.sql`SELECT password FROM admins WHERE username = ${'mainadmin'}`;
        if (!mainAdmin) {
            return res.status(400).json({ success: false, message: 'Main admin not found' });
        }

        const isMainAdminPasswordMatch = await bcrypt.compare(mainAdminPassword, mainAdmin.password);
        if (!isMainAdminPasswordMatch) {
            return res.status(400).json({ success: false, message: 'Incorrect main admin password' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.sql`INSERT INTO admins (username, password) VALUES (${username}, ${hashedPassword})`;
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
