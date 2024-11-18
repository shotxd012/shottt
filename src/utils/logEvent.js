const db = require(`${process.cwd()}/src/db`);

const logEvent = (guildId, logType, logTitle, logDescription) => {
    const query = `
        INSERT INTO guild_logs (guild_id, log_type, log_title, log_description, log_timestamp)
        VALUES (?, ?, ?, ?, NOW())
    `;
    const values = [guildId, logType, logTitle, logDescription];

    db.query(query, values, (err, result) => {
        if (err) {
            console.error('MySQL error:', err);
        } else {
            console.log('Log recorded in the database');
        }
    });
};

module.exports = logEvent;
