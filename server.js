const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('Missing JWT_SECRET in .env file. Add a line such as: JWT_SECRET=any-long-random-text');
    process.exit(1);
}
const ADMIN = 'Administrator', LECT = 'Lecturer', STUDENT = 'Student';

// ================= MIDDLEWARE =================
app.use(cors());
app.use(express.json());
app.use((req, res, next) => { req.body ??= {}; next(); });
app.use(morgan('dev')); // Logging middleware

// Rate limiting (general + stricter for login)
app.use('/api', rateLimit({
    windowMs: 15 * 60 * 1000, limit: 1000,
    message: { error: 'Too many requests. Please try again later.' }
}));
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, limit: 30,
    message: { error: 'Too many login attempts. Please try again in 15 minutes.' }
});

// Authentication middleware (JWT) + role-based access control
const auth = (req, res, next) => {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Authentication required. Please log in.' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Invalid or expired token. Please log in again.' });
    }
};
const allow = (...roles) => [auth, (req, res, next) =>
    roles.includes(req.user.role)
        ? next()
        : res.status(403).json({ error: `Access denied. Requires role: ${roles.join(' or ')}.` })];

// Request validation middleware. Rules: 'type' (required) or 'type?' (optional)
const checks = {
    str: v => typeof v === 'string' && v.trim().length > 0,
    int: v => /^\d+$/.test(String(v)) && Number(v) > 0,
    mark: v => v !== '' && !isNaN(v) && Number(v) >= 0 && Number(v) <= 100,
    date: v => /^\d{4}-\d{2}-\d{2}$/.test(v),
    time: v => /^\d{2}:\d{2}(:\d{2})?$/.test(v),
    email: v => typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
    pass: v => typeof v === 'string' && v.length >= 6,
    role: v => [ADMIN, LECT, STUDENT].includes(v)
};
const validate = rules => (req, res, next) => {
    const errors = [];
    for (const [field, spec] of Object.entries(rules)) {
        const optional = spec.endsWith('?'), type = spec.replace('?', '');
        const v = req.body[field];
        if (v === undefined || v === null || v === '') { if (!optional) errors.push(`${field} is required`); continue; }
        if (!checks[type](v)) errors.push(`${field} is invalid (expected ${type})`);
    }
    if (errors.length) return res.status(400).json({ error: 'Validation failed: ' + errors.join('; ') });
    next();
};
const timeOrder = (req, res, next) =>
    req.body.endTime > req.body.startTime
        ? next()
        : res.status(400).json({ error: 'Validation failed: endTime must be later than startTime' });

// Every :id in a URL must be a positive number
app.param('id', (req, res, next, v) =>
    /^\d+$/.test(v) ? next() : res.status(400).json({ error: 'Valid ID is required.' }));

// ================= DATABASE =================
const dbConfig = {
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};
let pool;

async function initDatabase() {
    try {
        pool = mysql.createPool(dbConfig);
        const connection = await pool.getConnection();
        console.log(`Successfully connected to MySQL database: "${dbConfig.database}"`);
        connection.release();
        const [users] = await pool.query('SELECT COUNT(*) as count FROM users');
        console.log(`Connected! Found ${users[0].count} existing user records in "users" table.`);
    } catch (err) {
        console.error('Database Connection Error:', err.message);
    }
}

// ================= HELPERS =================
const gradeOf = m => {
    const t = [[80, 'A'], [75, 'A-'], [70, 'B+'], [65, 'B'], [60, 'B-'], [55, 'C+'], [50, 'C']];
    const hit = t.find(([min]) => m >= min);
    return hit ? [hit[1], 'PASS'] : ['F', 'FAIL'];
};

// Generic list: filtering (?role=), search (?search=), sorting (?sort=&order=),
// pagination (?page=&limit=). Without ?page the response stays a plain array.
async function list(req, res, { sql, search = [], filters = {}, sortable, scope = null }) {
    const where = [], params = [];
    if (scope) { where.push(scope.sql); params.push(scope.value); }
    for (const [param, col] of Object.entries(filters)) {
        if (req.query[param]) { where.push(`${col} = ?`); params.push(String(req.query[param])); }
    }
    if (req.query.search && search.length) {
        where.push('(' + search.map(c => `${c} LIKE ?`).join(' OR ') + ')');
        search.forEach(() => params.push(`%${req.query.search}%`));
    }
    const whereSql = where.length ? ' WHERE ' + where.join(' AND ') : '';
    const sortCol = Object.hasOwn(sortable, req.query.sort) ? sortable[req.query.sort] : Object.values(sortable)[0];
    const dir = String(req.query.order).toLowerCase() === 'desc' ? 'DESC' : 'ASC';
    const orderSql = ` ORDER BY ${sortCol} ${dir}`;

    if (!req.query.page) {
        const [rows] = await pool.query(sql + whereSql + orderSql, params);
        return res.json(rows);
    }
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 10, 1), 100);
    const [[{ total }]] = await pool.query(`SELECT COUNT(*) AS total FROM (${sql}${whereSql}) t`, params);
    const [data] = await pool.query(sql + whereSql + orderSql + ' LIMIT ? OFFSET ?', [...params, limit, (page - 1) * limit]);
    res.json({ data, page, limit, total, totalPages: Math.ceil(total / limit) });
}

const updated = (res, r, label, id, body) =>
    r.affectedRows ? res.json(body) : res.status(404).json({ error: `${label} with ID ${id} not found.` });

const remove = (table, idCol, label) => async (req, res) => {
    try {
        const [r] = await pool.query(`DELETE FROM ${table} WHERE ${idCol} = ?`, [req.params.id]);
        if (!r.affectedRows) return res.status(404).json({ error: `${label} with ID ${req.params.id} not found.` });
        res.json({ success: true, message: `${label} #${req.params.id} deleted successfully.` });
    } catch (err) {
        if (String(err.code).startsWith('ER_ROW_IS_REFERENCED')) {
            return res.status(409).json({ error: `Cannot delete ${label.toLowerCase()} because related records exist in the database.` });
        }
        throw err;
    }
};

// ================= PAGES & HEALTH =================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/logo.svg', (req, res) => res.sendFile(path.join(__dirname, 'logo.svg')));
app.get('/api/health', (req, res) =>
    res.json({ status: 'Online', message: 'ExamSync SWC3633 API Engine Connected to Database' }));

// ================= AUTH =================
app.post('/api/login', loginLimiter, validate({ email: 'str', password: 'str' }), async (req, res) => {
    const { email, password } = req.body;
    const [rows] = await pool.query(
        `SELECT user_id AS id, full_name AS name, email, password, role, student_id AS studentMatricNo
         FROM users WHERE LOWER(email) = LOWER(?)`, [email]);
    const user = rows[0];
    let ok = false;
    if (user) {
        ok = /^\$2[aby]\$/.test(user.password)
            ? await bcrypt.compare(password, user.password)
            : password === user.password;
    }
    if (!ok) return res.status(401).json({ error: 'Invalid email address or password.' });
    delete user.password;
    const token = jwt.sign({ id: user.id, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ message: 'Login successful', token, user });
});

// ================= USERS (Admin; Lecturer may read) =================
app.get('/api/users', ...allow(ADMIN, LECT), (req, res) => list(req, res, {
    sql: 'SELECT user_id AS id, full_name AS name, email, role, student_id AS studentMatricNo FROM users',
    search: ['full_name', 'email', 'student_id'], filters: { role: 'role' },
    sortable: { id: 'user_id', name: 'full_name', email: 'email', role: 'role' }
}));

app.post('/api/users', ...allow(ADMIN),
    validate({ fullName: 'str', email: 'email', password: 'pass', role: 'role', studentId: 'str?' }),
    async (req, res) => {
        const { fullName, email, password, role, studentId } = req.body;
        const [r] = await pool.query(
            'INSERT INTO users (full_name, email, password, role, student_id) VALUES (?, ?, ?, ?, ?)',
            [fullName, email, await bcrypt.hash(password, 10), role, studentId || null]);
        res.status(201).json({
            message: 'User created successfully in database',
            user: { id: r.insertId, name: fullName, email, role, studentMatricNo: studentId || null }
        });
    });

app.put('/api/users/:id', ...allow(ADMIN),
    validate({ fullName: 'str', email: 'email', role: 'role', studentId: 'str?', password: 'pass?' }),
    async (req, res) => {
        const { fullName, email, password, role, studentId } = req.body;
        const sets = ['full_name = ?', 'email = ?', 'role = ?', 'student_id = ?'];
        const params = [fullName, email, role, studentId || null];
        if (password) { sets.push('password = ?'); params.push(await bcrypt.hash(password, 10)); }
        const [r] = await pool.query(`UPDATE users SET ${sets.join(', ')} WHERE user_id = ?`, [...params, req.params.id]);
        updated(res, r, 'User', req.params.id, { message: 'User updated successfully', id: Number(req.params.id) });
    });

app.delete('/api/users/:id', ...allow(ADMIN), remove('users', 'user_id', 'User'));

// ================= COURSES =================
app.get('/api/courses', auth, (req, res) => list(req, res, {
    sql: 'SELECT course_id AS id, course_code AS code, course_name AS title, credit_hour AS credits, faculty FROM courses',
    search: ['course_code', 'course_name', 'faculty'], filters: { faculty: 'faculty' },
    sortable: { id: 'course_id', code: 'course_code', title: 'course_name', credits: 'credit_hour' }
}));

const courseRules = validate({ code: 'str', title: 'str', credits: 'int?', faculty: 'str?' });

app.post('/api/courses', ...allow(ADMIN), courseRules, async (req, res) => {
    const { code, title, credits, faculty } = req.body;
    const [r] = await pool.query(
        'INSERT INTO courses (course_code, course_name, credit_hour, faculty) VALUES (?, ?, ?, ?)',
        [code, title, credits || 3, faculty || 'Faculty of Computing']);
    res.status(201).json({ id: r.insertId, code, title, credits, faculty });
});

app.put('/api/courses/:id', ...allow(ADMIN), courseRules, async (req, res) => {
    const { code, title, credits, faculty } = req.body;
    const [r] = await pool.query(
        'UPDATE courses SET course_code = ?, course_name = ?, credit_hour = ?, faculty = ? WHERE course_id = ?',
        [code, title, credits || 3, faculty || 'Faculty of Computing', req.params.id]);
    updated(res, r, 'Course', req.params.id, { id: Number(req.params.id), code, title, credits, faculty });
});

app.delete('/api/courses/:id', ...allow(ADMIN), remove('courses', 'course_id', 'Course'));

// ================= VENUES =================
app.get('/api/venues', auth, (req, res) => list(req, res, {
    sql: 'SELECT venue_id AS venueId, venue_name AS name, building, capacity FROM venues',
    search: ['venue_name', 'building'], filters: { building: 'building' },
    sortable: { id: 'venue_id', name: 'venue_name', building: 'building', capacity: 'capacity' }
}));

const venueRules = validate({ name: 'str', building: 'str', capacity: 'int' });

app.post('/api/venues', ...allow(ADMIN), venueRules, async (req, res) => {
    const { name, building, capacity } = req.body;
    const [r] = await pool.query('INSERT INTO venues (venue_name, building, capacity) VALUES (?, ?, ?)',
        [name, building, capacity]);
    res.status(201).json({ venueId: r.insertId, name, building, capacity });
});

app.put('/api/venues/:id', ...allow(ADMIN), venueRules, async (req, res) => {
    const { name, building, capacity } = req.body;
    const [r] = await pool.query('UPDATE venues SET venue_name = ?, building = ?, capacity = ? WHERE venue_id = ?',
        [name, building, capacity, req.params.id]);
    updated(res, r, 'Venue', req.params.id, { venueId: Number(req.params.id), name, building, capacity });
});

app.delete('/api/venues/:id', ...allow(ADMIN), remove('venues', 'venue_id', 'Venue'));

// ================= EXAMINATIONS =================
app.get('/api/examinations', auth, (req, res) => list(req, res, {
    sql: `SELECT e.examination_id AS id, e.course_id AS courseId, c.course_code AS courseCode,
                 c.course_name AS title, e.venue_id AS venueId, v.venue_name AS venue, v.building,
                 DATE_FORMAT(e.exam_date, '%Y-%m-%d') AS date, e.start_time AS startTime,
                 e.end_time AS endTime, e.exam_type AS examType, 'Scheduled' AS status
          FROM examinations e
          LEFT JOIN courses c ON e.course_id = c.course_id
          LEFT JOIN venues v ON e.venue_id = v.venue_id`,
    search: ['c.course_code', 'c.course_name', 'v.venue_name'],
    filters: { courseId: 'e.course_id', venueId: 'e.venue_id', examType: 'e.exam_type' },
    sortable: { date: 'e.exam_date', id: 'e.examination_id', course: 'c.course_code', venue: 'v.venue_name' }
}));

const examRules = [validate({ courseId: 'int', venueId: 'int', examDate: 'date', startTime: 'time', endTime: 'time', examType: 'str?' }), timeOrder];

app.post('/api/examinations', ...allow(ADMIN), ...examRules, async (req, res) => {
    const { courseId, venueId, examDate, startTime, endTime, examType } = req.body;
    const [r] = await pool.query(
        'INSERT INTO examinations (course_id, venue_id, exam_date, start_time, end_time, exam_type) VALUES (?, ?, ?, ?, ?, ?)',
        [courseId, venueId, examDate, startTime, endTime, examType || 'Final Examination']);
    res.status(201).json({ id: r.insertId, message: 'Exam scheduled successfully' });
});

app.put('/api/examinations/:id', ...allow(ADMIN), ...examRules, async (req, res) => {
    const { courseId, venueId, examDate, startTime, endTime, examType } = req.body;
    const [r] = await pool.query(
        `UPDATE examinations SET course_id = ?, venue_id = ?, exam_date = ?, start_time = ?, end_time = ?, exam_type = ?
         WHERE examination_id = ?`,
        [courseId, venueId, examDate, startTime, endTime, examType || 'Final Examination', req.params.id]);
    updated(res, r, 'Examination', req.params.id, { id: Number(req.params.id), message: 'Exam updated successfully' });
});

app.delete('/api/examinations/:id', ...allow(ADMIN), remove('examinations', 'examination_id', 'Examination'));

// ================= RESULTS (Lecturer/Admin write; students see only their own) =================
app.get('/api/results', auth, (req, res) => list(req, res, {
    sql: `SELECT r.result_id AS id, r.student_id AS studentUserId, u.full_name AS studentName,
                 u.student_id AS studentMatricNo, r.examination_id AS examinationId,
                 c.course_code AS courseCode, c.course_name AS courseName, r.marks, r.grade, r.status
          FROM results r
          LEFT JOIN users u ON r.student_id = u.user_id
          LEFT JOIN examinations e ON r.examination_id = e.examination_id
          LEFT JOIN courses c ON e.course_id = c.course_id`,
    scope: req.user.role === STUDENT ? { sql: 'r.student_id = ?', value: req.user.id } : null,
    search: ['u.full_name', 'u.student_id', 'c.course_code', 'c.course_name'],
    filters: { status: 'r.status', grade: 'r.grade', examinationId: 'r.examination_id' },
    sortable: { id: 'r.result_id', marks: 'r.marks', grade: 'r.grade', student: 'u.full_name' }
}));

app.post('/api/results', ...allow(LECT, ADMIN),
    validate({ studentId: 'int', examinationId: 'int', marks: 'mark' }),
    async (req, res) => {
        const { studentId, examinationId } = req.body;
        const marks = Number(req.body.marks);
        const [grade, status] = gradeOf(marks);
        const [r] = await pool.query(
            'INSERT INTO results (student_id, examination_id, marks, grade, status) VALUES (?, ?, ?, ?, ?)',
            [studentId, examinationId, marks, grade, status]);
        res.status(201).json({ id: r.insertId, studentId, examinationId, marks, grade, status });
    });

app.put('/api/results/:id', ...allow(LECT, ADMIN), validate({ marks: 'mark' }), async (req, res) => {
    const marks = Number(req.body.marks);
    const [grade, status] = gradeOf(marks);
    const [r] = await pool.query('UPDATE results SET marks = ?, grade = ?, status = ? WHERE result_id = ?',
        [marks, grade, status, req.params.id]);
    updated(res, r, 'Result', req.params.id, { id: Number(req.params.id), marks, grade, status });
});

app.delete('/api/results/:id', ...allow(LECT, ADMIN), remove('results', 'result_id', 'Result'));

// ================= REGISTRATIONS (Admin write; students see only their own) =================
app.get('/api/registrations', auth, (req, res) => list(req, res, {
    sql: `SELECT reg.registration_id AS regId, reg.student_id AS studentId, u.full_name AS studentName,
                 u.student_id AS matricNo, reg.course_id AS courseId, c.course_code AS courseCode,
                 c.course_name AS courseName, reg.semester,
                 DATE_FORMAT(reg.registration_date, '%Y-%m-%d') AS registrationDate
          FROM registrations reg
          LEFT JOIN users u ON reg.student_id = u.user_id
          LEFT JOIN courses c ON reg.course_id = c.course_id`,
    scope: req.user.role === STUDENT ? { sql: 'reg.student_id = ?', value: req.user.id } : null,
    search: ['u.full_name', 'u.student_id', 'c.course_code', 'c.course_name'],
    filters: { semester: 'reg.semester', courseId: 'reg.course_id' },
    sortable: { id: 'reg.registration_id', date: 'reg.registration_date', student: 'u.full_name', course: 'c.course_code' }
}));

const regRules = validate({ studentId: 'int', courseId: 'int', semester: 'str' });

app.post('/api/registrations', ...allow(ADMIN), regRules, async (req, res) => {
    const { studentId, courseId, semester } = req.body;
    const [r] = await pool.query(
        'INSERT INTO registrations (student_id, course_id, semester, registration_date) VALUES (?, ?, ?, NOW())',
        [studentId, courseId, semester]);
    res.status(201).json({ regId: r.insertId, message: 'Registration saved successfully' });
});

app.put('/api/registrations/:id', ...allow(ADMIN), regRules, async (req, res) => {
    const { studentId, courseId, semester } = req.body;
    const [r] = await pool.query(
        'UPDATE registrations SET student_id = ?, course_id = ?, semester = ? WHERE registration_id = ?',
        [studentId, courseId, semester, req.params.id]);
    updated(res, r, 'Registration', req.params.id, { regId: Number(req.params.id), message: 'Registration updated successfully' });
});

app.delete('/api/registrations/:id', ...allow(ADMIN), remove('registrations', 'registration_id', 'Registration'));

// ================= QR VERIFICATION PAGE (public) =================
function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function verifyPage(title, color, body) {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ExamSync Verification</title></head>
    <body style="font-family:monospace;background:#008080;padding:16px">
      <div style="max-width:480px;margin:auto;background:#c0c0c0;border:2px solid #000;padding:16px">
        <h2 style="margin-top:0">EXAMSYNC - EXAM SLIP VERIFICATION</h2>
        <div style="background:${color};color:#fff;padding:8px;font-weight:bold">${title}</div>
        ${body}
      </div></body></html>`;
}

app.get('/verify/:matric', async (req, res) => {
    try {
        const [users] = await pool.query(
            "SELECT user_id, full_name, student_id FROM users WHERE student_id = ? AND role = 'Student'",
            [req.params.matric]);
        if (users.length === 0) {
            return res.status(404).send(verifyPage('✘ INVALID - STUDENT NOT FOUND', '#b00020', ''));
        }
        const u = users[0];
        const [exams] = await pool.query(`
            SELECT c.course_code, c.course_name, DATE_FORMAT(e.exam_date, '%Y-%m-%d') AS date,
                   e.start_time, e.end_time, v.venue_name, v.building
            FROM registrations r
            JOIN courses c ON c.course_id = r.course_id
            JOIN examinations e ON e.course_id = r.course_id
            LEFT JOIN venues v ON v.venue_id = e.venue_id
            WHERE r.student_id = ? ORDER BY e.exam_date`, [u.user_id]);
        const rows = exams.map(x => `
            <tr><td>${esc(x.course_code)}<br><small>${esc(x.course_name)}</small></td>
                <td>${esc(x.date)}<br><small>${esc(x.start_time)} - ${esc(x.end_time)}</small></td>
                <td>${esc(x.venue_name)}<br><small>${esc(x.building)}</small></td></tr>`).join('');
        res.send(verifyPage('✔ VERIFIED STUDENT', '#006400', `
            <p><b>Name:</b> ${esc(u.full_name)}<br><b>Matric No:</b> ${esc(u.student_id)}</p>
            <table border="1" cellpadding="6" style="width:100%;border-collapse:collapse;background:#fff;font-size:12px">
              <tr><th>Course</th><th>Date / Time</th><th>Venue</th></tr>
              ${rows || '<tr><td colspan="3">No registered exams found.</td></tr>'}
            </table>`));
    } catch (err) {
        console.error(err);
        res.status(500).send(verifyPage('SERVER ERROR', '#b00020', ''));
    }
});

// ================= CENTRALISED ERROR HANDLING =================
app.use('/api', (req, res) =>
    res.status(404).json({ error: `Route ${req.method} ${req.originalUrl} not found.` }));

app.use((err, req, res, next) => {
    const dbErrors = {
        ER_DUP_ENTRY: [409, 'A record with the same unique value already exists (e.g. email already registered).'],
        ER_NO_REFERENCED_ROW_2: [400, 'Referenced record does not exist (check the student, course, venue or examination ID).'],
        ER_BAD_NULL_ERROR: [400, 'A required field is missing.'],
        ER_DATA_TOO_LONG: [400, 'A value is too long for its field.'],
        ER_TRUNCATED_WRONG_VALUE: [400, 'A value has an invalid format.']
    };
    if (dbErrors[err.code]) return res.status(dbErrors[err.code][0]).json({ error: dbErrors[err.code][1] });
    if (err.status && err.status < 500) {
        return res.status(err.status).json({ error: err.type === 'entity.parse.failed' ? 'Invalid JSON in request body.' : err.message });
    }
    console.error(err);
    res.status(500).json({ error: 'Internal server error.' });
});

// ================= START =================
app.listen(PORT, async () => {
    console.log(`Server running on http://localhost:${PORT}`);
    await initDatabase();
});
