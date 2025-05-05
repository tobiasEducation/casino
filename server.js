const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const chalk = require('chalk');

const app = express();

// Middleware to parse URL form data and JSON
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Helper function for logging
function logEvent(type, message, isError = false, related = false) {
    const timestamp = new Date().toISOString();
    
    // Only print separator if this is not a related event
    if (!related) {
        console.log(chalk.gray('\n----------------------------------------'));
        console.log(chalk.blue(`⏰ [${timestamp}]`));
    }
    
    switch(type) {
        case 'REQUEST':
            console.log(chalk.cyan(`📡 ${message}`));
            break;
        case 'LOGIN':
            console.log(chalk.yellow(`🔐 ${message}`));
            break;
        case 'REGISTER':
            console.log(chalk.magenta(`📝 ${message}`));
            break;
        case 'SUCCESS':
            console.log(chalk.green(`✅ ${message}`));
            break;
        case 'ERROR':
            console.log(chalk.red(`❌ ${message}`));
            break;
        default:
            console.log(chalk.white(`ℹ️  ${message}`));
    }
    
    if (!related) {
        console.log(chalk.gray('----------------------------------------'));
    }
}

app.use((req, res, next) => {
    logEvent('REQUEST', `${req.method} ${req.url}`);
    next();
});

app.use(express.static(path.join(__dirname, 'public')));

// Database
const db = new sqlite3.Database('./spill.db', (err) => {
    if (err) {
     console.error(chalk.red('❌ Database Connection Error:', err.message));
    } else {
        console.log(chalk.green('✅ Connected to SQLite database'));
    }
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    logEvent('LOGIN', `Attempt for user: ${username}`);
    
    if (!username || !password) {
        logEvent('ERROR', `Login failed: Missing credentials for ${username}`, true, true);
        return res.json({ success: false, message: 'Username and password are required' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            logEvent('ERROR', `Database Error: ${err.message}`, true, true);
            return res.json({ success: false, message: 'Database error occurred' });
        }

        if (!user) {
            logEvent('ERROR', `Login failed: User not found - ${username}`, true, true);
            return res.json({ success: false, message: 'Invalid username or password' });
        }

        try {
            const match = await bcrypt.compare(password, user.password_hash);
            if (match) {
                logEvent('SUCCESS', `Login successful for user: ${username}`, false, true);
                console.log('Sending user data:', { id: user.id, username: user.username });
                res.json({ 
                    success: true, 
                    message: 'Login successful',
                    userId: user.id,
                    username: user.username
                });
            } else {
                logEvent('ERROR', `Login failed: Invalid password for ${username}`, true, true);
                res.json({ success: false, message: 'Invalid username or password' });
            }
        } catch (error) {
            logEvent('ERROR', `Authentication Error: ${error.message}`, true, true);
            res.json({ success: false, message: 'Authentication error occurred' });
        }
    });
});

// GET route for register page
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// GET /api/leaderboard?game=blackjack
app.get('/api/leaderboard', (req, res) => {
    const game = req.query.game || 'blackjack';
    db.all(
      `SELECT u.id    AS userId,
              u.username,
              l.score
       FROM leaderboard l
       JOIN users u ON u.id = l.user_id
       WHERE l.game_id = ?
       ORDER BY l.score DESC`,
      [game],
      (err, rows) => {
        if (err) return res.status(500).json([]);
        res.json(rows);
      }
    );
  });
  

// POST route for handling registrations
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    const confirmPassword = req.body['confirm-password'];
    logEvent('REGISTER', `New registration attempt for user: ${username}`);

    if (!username || !email || !password || !confirmPassword) {
        logEvent('ERROR', `Registration failed: Missing fields for ${username}`, true);
        return res.json({ 
            success: false, 
            message: 'All fields are required.' 
        });
    }

    // Check if passwords match
    if (password !== confirmPassword) {
        logEvent('ERROR', `Registration failed: Passwords do not match for ${username}`, true);
        return res.json({ 
            success: false, 
            message: 'Passwords do not match.' 
        });
    }

    // Check if username is already taken
    try {
        db.get('SELECT username FROM users WHERE username = ?', [username], async (err, user) => {
            if (err) {
                logEvent('ERROR', `Database Error: ${err.message}`, true);
                return res.json({ success: false, message: 'Database error occurred' });
            }

            if (user) {
                logEvent('ERROR', `Registration failed: Username already exists - ${username}`, true);
                return res.json({ 
                    success: false, 
                    message: 'Username already taken.' 
                });
            }

            // Hash password
            try {
                const saltRounds = 10;
                const password_hash = await bcrypt.hash(password, saltRounds);

                db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                    [username, password_hash], 
                    (err) => {
                        if (err) {
                     logEvent('ERROR', `Database Error: ${err.message}`, true);
                     return res.json({ 
                       success: false, 
                      message: 'Error creating user account.' 
                            });
                }

                // Log success and send response
                logEvent('SUCCESS', `Successfully registered new user: ${username}`);
                res.json({ 
                    success: true, 
                  message: `Registration successful! Welcome, ${username}!` 
                        });
                    }
                );
            } catch (error) {
                logEvent('ERROR', `Registration Error: ${error.message}`, true);
                res.json({ 
                    success: false, 
                    message: 'Error processing registration.' 
                });
            }
        });
    } catch (error) {
        logEvent('ERROR', `Registration Error: ${error.message}`, true);
        res.json({ 
            success: false, 
            message: 'Error processing registration.' 
        });
    }
});

// Add this utility function at the top of server.js for detailed request logging
function logRequestDetails(req, type = 'REQUEST') {
    console.log('\n' + chalk.gray('========== REQUEST DETAILS =========='));
    console.log(chalk.blue(`⏰ Timestamp: ${new Date().toISOString()}`));
    console.log(chalk.yellow(`📍 Endpoint: ${req.method} ${req.url}`));
    console.log(chalk.cyan('📦 Request Body:'), req.body);
    console.log(chalk.magenta('🔑 Auth Headers:'), req.headers.authorization || 'None');
    console.log(chalk.white('🌐 Client IP:'), req.ip);
    console.log(chalk.gray('====================================\n'));
}

// Modify the updateScore endpoint with detailed logging
app.post('/api/updateScore', (req, res) => {
    const { userId, gameId, score } = req.body;
    
    console.log('Score update request:', { userId, gameId, score });

    // First check if a record exists for this user and game
    db.get(
        'SELECT id FROM leaderboard WHERE user_id = ? AND game_id = ?',
        [userId, gameId],
        (err, record) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ success: false, message: 'Database error' });
            }

            if (record) {
                // Update existing record
                db.run(
                    'UPDATE leaderboard SET score = score + ? WHERE user_id = ? AND game_id = ?',
                    [score, userId, gameId],
                    function(err) {
                        if (err) {
                            console.error('Update error:', err);
                            return res.status(500).json({ success: false, message: 'Error updating score' });
                        }
                        res.json({ success: true, message: 'Score updated successfully' });
                    }
                );
            } else {
                // Insert new record if none exists
                db.run(
                    'INSERT INTO leaderboard (user_id, game_id, score) VALUES (?, ?, ?)',
                    [userId, gameId, score],
                    function(err) {
                        if (err) {
                            console.error('Insert error:', err);
                            return res.status(500).json({ success: false, message: 'Error creating score' });
                        }
                        res.json({ success: true, message: 'Score created successfully' });
                    }
                );
            }
        }
    );
});

// Server startup
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log('\n' + chalk.gray('========================================'));
    console.log(chalk.green(`🚀 Server Status: ONLINE`));
    console.log(chalk.green(`🌐 Port: ${PORT}`));
    console.log(chalk.green(`📝 Logging: ENABLED`));
    console.log(chalk.gray('========================================\n'));
}).on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        logEvent('ERROR', `Port ${PORT} is already in use`);
    } else {
        logEvent('ERROR', `Server error: ${err.message}`);
    }
});

// Handle server shutdown
process.on('SIGINT', () => {
    console.log(chalk.yellow('\n\n🛑 Shutting down server...'));
    db.close((err) => {
        if (err) {
            console.error(chalk.red('❌ Error closing database:', err.message));
        } else {
            console.log(chalk.green('✅ Database connection closed'));
        }
        process.exit(0);
    });
});


