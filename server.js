const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MySQL Connection Pool Configuration
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'Danziq123',
    database: process.env.DB_NAME || 'exam_management',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

let pool;

// Initialize Database & Connect
async function initDatabase() {
    try {
        pool = mysql.createPool(dbConfig);
        const connection = await pool.getConnection();
        console.log(`Successfully connected to MySQL database: "${dbConfig.database}"`);
        connection.release();

        // Check user count in existing table
        const [users] = await pool.query('SELECT COUNT(*) as count FROM users');
        console.log(`Connected! Found ${users[0].count} existing user records in "users" table.`);

    } catch (err) {
        console.error('Database Connection Error:', err.message);
        console.error('Please verify DB_HOST, DB_USER, DB_PASSWORD, and DB_NAME in .env file.');
    }
}

// Root Health Check
app.get('/', (req, res) => {
    res.json({ status: 'Online', message: 'ExamSync SWC3633 API Engine Connected to Database' });
});

// ================= USER ENDPOINTS =================

// POST /api/login - Authenticate user credentials against database
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        const [rows] = await pool.query(
            `SELECT 
                user_id AS id, 
                full_name AS name, 
                email, 
                password,
                role, 
                student_id AS studentMatricNo 
            FROM users 
            WHERE LOWER(email) = LOWER(?)`,
            [email]
        );

        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid email address or password.' });
        }

        const user = rows[0];

        let isMatch = false;
        if (user.password.startsWith('$2b$') || user.password.startsWith('$2a$')) {
            isMatch = await bcrypt.compare(password, user.password);
        } else {
            isMatch = (password === user.password);
        }

        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email address or password.' });
        }

        delete user.password;
        res.json({ message: 'Login successful', user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /api/users - Fetch all users
app.get('/api/users', async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT 
                user_id AS id, 
                full_name AS name, 
                email, 
                role, 
                student_id AS studentMatricNo 
            FROM users 
            ORDER BY user_id ASC
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/users - Add a new user with hashed password
app.post('/api/users', async (req, res) => {
    const { fullName, email, password, role, studentId } = req.body;

    if (!fullName || !email || !password || !role) {
        return res.status(400).json({ error: 'Full name, email, password, and role are required.' });
    }

    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const [result] = await pool.query(
            'INSERT INTO users (full_name, email, password, role, student_id) VALUES (?, ?, ?, ?, ?)',
            [fullName, email, hashedPassword, role, studentId || null]
        );

        const newUser = {
            id: result.insertId,
            name: fullName,
            email,
            role,
            studentMatricNo: studentId || null
        };

        res.status(201).json({ message: 'User created successfully in database', user: newUser });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ error: 'Email address is already registered.' });
        }
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/users/:id - Delete a user account
app.delete('/api/users/:id', async (req, res) => {
    const { id } = req.params;

    if (!id || isNaN(id)) {
        return res.status(400).json({ error: 'Valid user ID is required.' });
    }

    try {
        const [result] = await pool.query('DELETE FROM users WHERE user_id = ?', [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: `User with ID ${id} not found.` });
        }

        return res.status(200).json({ success: true, message: `User #${id} deleted successfully.` });
    } catch (err) {
        if (err.code === 'ER_ROW_IS_REFERENCED_2' || err.code === 'ER_ROW_IS_REFERENCED') {
            return res.status(409).json({
                error: 'Cannot delete user because they have related records (results or registrations) in the database.'
            });
        }
        return res.status(500).json({ error: err.message });
    }
});

// ================= COURSE ENDPOINTS =================

app.get('/api/courses', async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT 
                course_id AS id, 
                course_code AS code, 
                course_name AS title, 
                credit_hour AS credits, 
                faculty 
            FROM courses 
            ORDER BY course_id ASC
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/courses', async (req, res) => {
    const { code, title, credits, faculty } = req.body;
    try {
        const [result] = await pool.query(
            'INSERT INTO courses (course_code, course_name, credit_hour, faculty) VALUES (?, ?, ?, ?)',
            [code, title, credits || 3, faculty || 'Faculty of Computing']
        );
        res.status(201).json({ id: result.insertId, code, title, credits, faculty });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/courses/:id - Delete a course
app.delete('/api/courses/:id', async (req, res) => {
    const { id } = req.params;

    if (!id || isNaN(id)) {
        return res.status(400).json({ error: 'Valid course ID is required.' });
    }

    try {
        const [result] = await pool.query('DELETE FROM courses WHERE course_id = ?', [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: `Course with ID ${id} not found.` });
        }

        return res.status(200).json({ success: true, message: `Course #${id} deleted successfully.` });
    } catch (err) {
        if (err.code === 'ER_ROW_IS_REFERENCED_2' || err.code === 'ER_ROW_IS_REFERENCED') {
            return res.status(409).json({
                error: 'Cannot delete course because related examination or registration records exist in the database.'
            });
        }
        return res.status(500).json({ error: err.message });
    }
});

// ================= VENUE ENDPOINTS =================

app.get('/api/venues', async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT 
                venue_id AS venueId, 
                venue_name AS name, 
                building, 
                capacity 
            FROM venues 
            ORDER BY venue_id ASC
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/venues', async (req, res) => {
    const { name, building, capacity } = req.body;
    try {
        const [result] = await pool.query(
            'INSERT INTO venues (venue_name, building, capacity) VALUES (?, ?, ?)',
            [name, building, capacity]
        );
        res.status(201).json({ venueId: result.insertId, name, building, capacity });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/venues/:id - Delete a venue
app.delete('/api/venues/:id', async (req, res) => {
    const { id } = req.params;

    if (!id || isNaN(id)) {
        return res.status(400).json({ error: 'Valid venue ID is required.' });
    }

    try {
        const [result] = await pool.query('DELETE FROM venues WHERE venue_id = ?', [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: `Venue with ID ${id} not found.` });
        }

        return res.status(200).json({ success: true, message: `Venue #${id} deleted successfully.` });
    } catch (err) {
        if (err.code === 'ER_ROW_IS_REFERENCED_2' || err.code === 'ER_ROW_IS_REFERENCED') {
            return res.status(409).json({
                error: 'Cannot delete venue because related examination records exist in the database.'
            });
        }
        return res.status(500).json({ error: err.message });
    }
});

// ================= EXAMINATION ENDPOINTS =================

app.get('/api/examinations', async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT 
                e.examination_id AS id, 
                e.course_id AS courseId, 
                c.course_code AS courseCode, 
                c.course_name AS title, 
                e.venue_id AS venueId, 
                v.venue_name AS venue, 
                v.building, 
                DATE_FORMAT(e.exam_date, '%Y-%m-%d') AS date, 
                e.start_time AS startTime, 
                e.end_time AS endTime, 
                e.exam_type AS examType, 
                'Scheduled' AS status 
            FROM examinations e 
            LEFT JOIN courses c ON e.course_id = c.course_id 
            LEFT JOIN venues v ON e.venue_id = v.venue_id
            ORDER BY e.exam_date ASC
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/examinations', async (req, res) => {
    const { courseId, venueId, examDate, startTime, endTime, examType } = req.body;
    try {
        const [result] = await pool.query(
            'INSERT INTO examinations (course_id, venue_id, exam_date, start_time, end_time, exam_type) VALUES (?, ?, ?, ?, ?, ?)',
            [courseId, venueId, examDate, startTime, endTime, examType || 'Final Examination']
        );
        res.status(201).json({ id: result.insertId, message: 'Exam scheduled successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/examinations/:id - Delete an examination record
app.delete('/api/examinations/:id', async (req, res) => {
    const { id } = req.params;

    if (!id || isNaN(id)) {
        return res.status(400).json({ error: 'Valid examination ID is required.' });
    }

    try {
        const [result] = await pool.query('DELETE FROM examinations WHERE examination_id = ?', [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: `Examination with ID ${id} not found.` });
        }

        return res.status(200).json({ success: true, message: `Examination #${id} deleted successfully.` });
    } catch (err) {
        if (err.code === 'ER_ROW_IS_REFERENCED_2' || err.code === 'ER_ROW_IS_REFERENCED') {
            return res.status(409).json({
                error: 'Cannot delete examination because related result records exist in the database.'
            });
        }
        return res.status(500).json({ error: err.message });
    }
});

// ================= RESULTS ENDPOINTS =================

app.get('/api/results', async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT 
                r.result_id AS id, 
                r.student_id AS studentUserId, 
                u.full_name AS studentName, 
                u.student_id AS studentMatricNo, 
                r.examination_id AS examinationId, 
                c.course_code AS courseCode, 
                c.course_name AS courseName, 
                r.marks, 
                r.grade, 
                r.status 
            FROM results r 
            LEFT JOIN users u ON r.student_id = u.user_id 
            LEFT JOIN examinations e ON r.examination_id = e.examination_id 
            LEFT JOIN courses c ON e.course_id = c.course_id
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/results', async (req, res) => {
    const { studentId, examinationId, marks } = req.body;

    let grade = 'F', status = 'FAIL';
    const numMarks = parseFloat(marks);
    if (numMarks >= 80) { grade = 'A'; status = 'PASS'; }
    else if (numMarks >= 75) { grade = 'A-'; status = 'PASS'; }
    else if (numMarks >= 70) { grade = 'B+'; status = 'PASS'; }
    else if (numMarks >= 65) { grade = 'B'; status = 'PASS'; }
    else if (numMarks >= 60) { grade = 'B-'; status = 'PASS'; }
    else if (numMarks >= 55) { grade = 'C+'; status = 'PASS'; }
    else if (numMarks >= 50) { grade = 'C'; status = 'PASS'; }

    try {
        const [result] = await pool.query(
            'INSERT INTO results (student_id, examination_id, marks, grade, status) VALUES (?, ?, ?, ?, ?)',
            [studentId, examinationId, numMarks, grade, status]
        );
        res.status(201).json({ id: result.insertId, studentId, examinationId, marks: numMarks, grade, status });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ================= REGISTRATION ENDPOINTS =================

app.get('/api/registrations', async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT 
                reg.registration_id AS regId, 
                reg.student_id AS studentId, 
                u.full_name AS studentName, 
                u.student_id AS matricNo, 
                reg.course_id AS courseId, 
                c.course_code AS courseCode, 
                c.course_name AS courseName, 
                reg.semester, 
                DATE_FORMAT(reg.registration_date, '%Y-%m-%d') AS registrationDate 
            FROM registrations reg 
            LEFT JOIN users u ON reg.student_id = u.user_id 
            LEFT JOIN courses c ON reg.course_id = c.course_id
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/registrations', async (req, res) => {
    const { studentId, courseId, semester } = req.body;
    try {
        const [result] = await pool.query(
            'INSERT INTO registrations (student_id, course_id, semester, registration_date) VALUES (?, ?, ?, NOW())',
            [studentId, courseId, semester]
        );
        res.status(201).json({ regId: result.insertId, message: 'Registration saved successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/registrations/:id - Delete a registration record
app.delete('/api/registrations/:id', async (req, res) => {
    const { id } = req.params;

    if (!id || isNaN(id)) {
        return res.status(400).json({ error: 'Valid registration ID is required.' });
    }

    try {
        const [result] = await pool.query('DELETE FROM registrations WHERE registration_id = ?', [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: `Registration with ID ${id} not found.` });
        }

        return res.status(200).json({ success: true, message: `Registration #${id} deleted successfully.` });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

// Start Express Server
app.listen(PORT, async () => {
    console.log(`Server running on http://localhost:${PORT}`);
    await initDatabase();
});