const http = require('http');
const express = require('express');
const morgan = require('morgan');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const es6Renderer = require('express-es6-template-engine');

const app = express();
const server = http.createServer(app);

const PORT = 3000;

const logger = morgan('tiny');

app.engine('html', es6Renderer);
app.set('views', 'templates');
app.set('view engine', 'html');

const Sequelize = require('sequelize');
const { User } = require('./models');

app.use(logger);

app.use(express.urlencoded({extended: true}));

app.get('/', (req, res) => {
    res.render('home')
});

app.get('/new', (req, res) => {
    res.render('login', {
        locals: {
            title: "Sign Up"
        }
    });
});

app.post('/new', async (req, res) => {
    const { username, password } = req.body;
    if (username === '' || password === '') {
        console.log('username or password is blank');
        res.redirect('/new');
    } else {
        const salt = bcrypt.genSaltSync(10); 
        const hash = bcrypt.hashSync(password, salt);
        try {
            const newUser = await User.create({
                username, 
                hash      
            });
            res.redirect('/login');                        
        } catch (e) {
            
            if (e.name === "SequelizeUniqueConstraintError") {
                console.log('username is taken')
                res.redirect('/new')
            }
            res.redirect('/new');
        }
    }
});

app.get('/login', (req, res) => {
    res.render('login', {
        locals: {
            title: "Login"
        }
    })
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({
        where: {
            username
        }
    });
    if (user) {
        console.log('valid user...checking password');
        const isValid = bcrypt.compareSync(password, user.hash);
        if (isValid) {
            console.log('password is good!');
            res.redirect('/members-only');
        } else {
            console.log('but password is wrong');
            res.redirect('/login');
        }
    } else {
        console.log('not a valid user');
        res.redirect('/login');
    }
});

app.get('/members-only', (req, res) => {
    res.render('member');
});


server.listen(PORT, () => {
    console.log(`Listening at http://localhost:${PORT}`);
});
