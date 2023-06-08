const express = require("express");
const winston = require('winston');
const session = require('express-session');
const passport = require('passport');
const JWTstrategy = require("passport-jwt").Strategy;
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs');
const fs = require("fs");
const authToken = require("./token.json");

let JWT_AUTH_TOKEN = '';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));
app.use(session({
    secret: 'xyzabc123secret', // secret
    resave: false,
    saveUninitialized: false
}));
app.use(passport.session());

const users = [];
const secret = 'akjdhfjhaksdhfhiaosdhfuiernsdjfojkasdndjashdjlk'
let r, a;

//logger configuration
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    defaultMeta: { service: 'calculator-microservice' },
    transports: [
        //
        // - Write all logs with importance level of `error` or less to `error.log`
        // - Write all logs with importance level of `info` or less to `combined.log`
        //
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' }),
    ],
});

app.post('/signin', (req, res, next) => {
    r = req.body
    next()
}, passport.authenticate('jwt', {
    session: true,
    successRedirect: '/calculator',
    failureRedirect: '/recheck-jwt'
}));


// funciton to get existing jwt token
function getJwtToken() {
    return authToken.Authorization?.substring(7);
}

passport.use(
    new JWTstrategy(
        {
            secretOrKey: secret,
            jwtFromRequest: getJwtToken,
        },
        async (authToken, done) => {
            if (authToken) {
                if (authToken.user?.email == "tokenerror") {
                    let testError = new Error(
                        "token error"
                    );
                    return done(testError, false);
                }
            }
            if (authToken.name[0].email !== users[0]?.email) {
                return done(null, false, { message: 'Incorrect username or password.' });
            } else {
                return done(null, { username: authToken.name[0].email });
            }

        }
    )

);

passport.serializeUser(function (data, done) {
    done(null, data.username);
});

passport.deserializeUser(function (usr, done) {
    done(null, { username: usr });
});

app.get('/recheck-jwt', async function (req, res) {
    try {
        if (!JWT_AUTH_TOKEN)
            return res.redirect('/');
        const data = jwt.verify(JWT_AUTH_TOKEN.substring(7), secret)
        let user;
        if (data && data.name)
            user = data.name.find(et => et.email === r.email)
        let result = await bcrypt.compare(r.password, user.password);
        if (!result) {
            a = false;
            user = false;
        }
        if (!user)
            return res.redirect('/')

        a=true;
        res.sendFile(__dirname + '/public/calculator.html');
    } catch (error) {
        res.status(500).send(`<h3>${error.toString()}</h3> <a href='/'>Home</a>`);
    }
})

app.get('/signup', function (req, res) {
    try {
        res.sendFile(__dirname + '/public/signup.html');
    } catch (error) {
        res.status(500).send(`<h3>${error.toString()}</h3> <a href='/'>Home</a>`);
    }
})


app.post('/signup', async (req, res) => {
    try {
        const hash = await bcrypt.hash(req.body.password, 8)
        users.push({
            email: req.body.email,
            password: hash
        })
        let token = jwt.sign({ name: users }, `${secret}`, { expiresIn: '80000ms' });
        JWT_AUTH_TOKEN = `Bearer ${token}`;
        fs.writeFile(
            "token.json",
            JSON.stringify({ Authorization: `Bearer ${token}` }),
            (err) => {
                if (err) throw err;
                res.redirect('/')
            }
        );
    } catch (error) {
        res.status(500).send(`<h3>${error.toString()}</h3> <a href='/'>Home</a>`);
    }
})

app.get('/', function (req, res) {
    try {
        res.sendFile(__dirname + '/public/signin.html');
    } catch (error) {
        res.status(500).send(`<h3>${error.toString()}</h3> <a href='/'>Home</a>`);
    }
})

function isAuthenticated(req, res, next) {
    if (!a)
        return res.redirect('/');
    else
        return next();

}



// function to log 
const logOperation = function (operation, num1, num2) {
    logger.log({
        level: 'info',
        message: `New ${operation} operation requested: ${num1} ${operation} ${num2}`
    })
}

// funciton to add num1 num2
const addition = (num1, num2) => {
    var ans = num1 + num2
    return ans;
}

// funciton to substract num1 num2
const subtraction = (num1, num2) => {
    var ans = num1 - num2;
    return ans;
}

// funciton to multiply num1 num2
const multiplication = (num1, num2) => {
    var ans = num1 * num2;
    return ans;
}

// funciton to divide num1 num2\
const division = (num1, num2) => {
    var ans = num1 / num2;
    return ans;
}

// calculator 
app.get('/calculator', isAuthenticated, function (req, res) {
    try {
        res.sendFile(__dirname + '/public/calculator.html');
    } catch (error) {
        res.status(500).send(`<h3>${error.toString()}</h3> <a href='/'>Home</a>`);
    }
})

app.post('/add', isAuthenticated, function (req, res) {
    try {
        if (isNaN(req.body.num1) || req.body.num1 == null || req.body.num1 == '')
            throw new Error("Number 1 incorrectly defined");
        if (isNaN(req.body.num2) || req.body.num2 == null || req.body.num2 == '')
            throw new Error("Number 2 incorrectly defined");
        let num1 = parseFloat(req.body.num1);
        let num2 = parseFloat(req.body.num2);
        logOperation('addition', num1, num2);
        res.send(`<div><h1>The sum of the two numbers is ${addition(num1, num2)}</h1><a href='/'>Home</a></div>`);
    } catch (err) {
        logger.error(err.toString());
        res.status(500).send(`<h3>${err.toString()}</h3> <a href='/'>Home</a>`);
    }
})

app.post('/subtract', isAuthenticated, function (req, res) {
    try {
        if (isNaN(req.body.num1) || req.body.num1 == null || req.body.num1 == '')
            throw new Error("Number 1 incorrectly defined");
        if (isNaN(req.body.num2) || req.body.num2 == null || req.body.num2 == '')
            throw new Error("Number 2 incorrectly defined");
        let num1 = parseFloat(req.body.num1);
        let num2 = parseFloat(req.body.num2);
        logOperation('subtraction', num1, num2);
        res.send(`<div><h1>The subtraction of the two numbers is ${subtraction(num1, num2)}</h1><a href='/'>Home</a></div>`);
    } catch (err) {
        logger.error(err.toString());
        res.status(500).send(`<h3>${err.toString()}</h3> <a href='/'>Home</a>`);
    }
})

app.post('/multiply', isAuthenticated, function (req, res) {
    try {
        if (isNaN(req.body.num1) || req.body.num1 == null || req.body.num1 == '')
            throw new Error("Number 1 incorrectly defined");
        if (isNaN(req.body.num2) || req.body.num2 == null || req.body.num2 == '')
            throw new Error("Number 2 incorrectly defined");
        let num1 = parseFloat(req.body.num1);
        let num2 = parseFloat(req.body.num2);
        logOperation('multiplication', num1, num2);
        res.send(`<div><h1>The multiplication of the two numbers is ${multiplication(num1, num2)}</h1><a href='/'>Home</a></div>`);
    } catch (err) {
        logger.error(err.toString());
        res.status(500).send(`<h3>${err.toString()}</h3> <a href='/'>Home</a>`);
    }
})

app.post('/divide', isAuthenticated, function (req, res) {
    try {
        if (isNaN(req.body.num1) || req.body.num1 == null || req.body.num1 == '')
            throw new Error("Number 1 incorrectly defined");
        if (isNaN(req.body.num2) || req.body.num2 == null || req.body.num2 == '')
            throw new Error("Number 2 incorrectly defined");
        let num1 = parseFloat(req.body.num1);
        let num2 = parseFloat(req.body.num2);
        logOperation('division', num1, num2);
        res.send(`<div><h1>The division of the two numbers is ${division(num1, num2)}</h1><a href='/'>Home</a></div>`);
    } catch (err) {
        logger.error(err.toString());
        res.status(500).send(`<h3>${err.toString()}</h3> <a href='/'>Home</a>`);
    }
})

var port = process.env.port || 3000;
app.listen(port, () => console.log(">> App listening at localhost:" + port));