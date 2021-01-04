require('dotenv').config();

const http = require('http');
const express = require('express');
const morgan = require('morgan');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const es6Renderer = require('express-es6-template-engine');

const session = require('express-session');
const FileStore = require('session-file-store')(session)

const { requireLogin, logout } = require('./auth')


const app = express();
const server = http.createServer(app);

const PORT = 3000;

const logger = morgan('tiny');

app.use(express.static('public'))
app.engine('html', es6Renderer);
app.set('views', 'templates');
app.set('view engine', 'html');

app.use(session({
    store: new FileStore(),  // no options for now
    secret: process.env.SESSION_SECRET,
    saveUninitialized: false,
    resave: true,
    rolling: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7 // how many ms until session expires, 1 week
    }
}));

const Sequelize = require('sequelize');
const { User, Note } = require('./models');

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
            req.session.user = {
                username,
                id: user.id
            };
            req.session.save(() => {
                res.redirect('/members-only');                
            });
            
        } else {
            console.log('but password is wrong');
            res.redirect('/login');
        }
    } else {
        console.log('not a valid user');
        res.redirect('/login');
    }
});

app.get('/members-only', requireLogin, (req, res) => {
    const { username } = req.session.user;
    res.render('member', {
        locals: {
            username
        }
    });
});


app.get('/note/create', requireLogin, (req,res)=>{
    res.render('note-form')
});

app.post('/note/create', async (req,res)=>{
    const { title } = req.body;
    const { content } = req.body;
    const { id } = req.session.user;
    if(title && id) {
        const newNote = await Note.create({
            title,
            content,
            userID: id
        });
        res.redirect('/note')
    } else {
        
        res.redirect('/members-only')
    };
});

app.get('/note', requireLogin, async (req,res)=>{
    const { id } = req.session.user;
    if (id) {
        const note = await Note.findAll({
            where: {
                userID: id
            }
        });
        res.render('note-list', {
            locals: {
                note
            }
        })
    } else {
        res.redirect('/')
    }
});

app.get('/note/:id', async (req,res)=>{
    console.log(`The id is ${req.params.id}`);
    const note = await Note.findByPk(req.params.id);
    res.render('note-id',{
        locals: {
            title: note.title,
            content: note.content
        }
    })
});


app.get('/note/:title', requireLogin, async (req,res)=>{
    const { title } = req.params;
    const { id } = req.session.user;

    if (id) {
        const note = await Note.findAll({
            where: {
                userID: id
            }
        });
        const foundTitle = note.find(n=>n.title == title);
        const fTitle = foundTitle.title;
        const fContent = foundTitle.content;
    res.render('note-page', {
        locals: {
            title,
            note,
            fTitle,
            fContent
        }
    })
}});

app.get('/search', requireLogin, (req,res)=>{
    res.render('note-search')
});

app.post('/search', requireLogin, async (req,res)=>{
    const { title } = req.body;
    const { id } = req.session.user;
    if (id) {
        const note = await Note.findAll({
            where: {
                userID: id,
                title
            }
        });
        res.render('note-search-list', {
            locals: {
                note
            }
        })
    }

})


app.get('/unauthorized', (req, res) => {
    res.send(`You shall not pass!`);
});

app.get('/logout', logout);

server.listen(PORT, () => {
    console.log(`Listening at http://localhost:${PORT}`);
});
