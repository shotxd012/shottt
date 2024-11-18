const mysql = require('mysql2');

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    connectionLimit: 10,
});

db.connect((err) => {
    if (err) {
        console.error('MySQL connection error:', err);
    } else {
        console.log('MySQL database connected successfully!');
    }
});

setInterval(() => {
    db.query('SELECT 1', (err) => {
        if (err) {
            console.error('Error refreshing MySQL connection:', err);
        } else {
            console.log('MySQL connection refreshed!');
        }
    });
}, 2 * 60 * 60 * 1000);

module.exports = db;
