import express from "express"
import { createServer } from "http"
import cors from "cors"
import dotenv from "dotenv"
import { connection } from "./connection.js"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import { Server } from "socket.io"


dotenv.config();

connection.connect((err) => {
    if(err) console.log("Something went wrong");
})

const app = express();
const server = createServer(app)
const io = new Server(server, {
    cors: {
        origin: "*"
    }
})

app.use(express.json())
app.use(cors())

export function authToken(req, res, next) {
    const authHeaders = req.headers['authorization'];
    const token = authHeaders && authHeaders.split(' ')[1];

    if(token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if(err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

const findSocketIdByLogin = (login) => {
    const sockets = [...io.sockets.sockets];

    const returnedValues = sockets.find(([socketId, socket]) => {
        return socket.user && socket.user.login === login
    })

    return returnedValues ? returnedValues[0] : null
}

io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if(!token) {
        return next(new Error("Token jest nieautoryzowany"));
    }

    jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
        if(err) return next(new Error("Authentication Error"))

        socket.user = {
            login: decoded.login,
            firstname: decoded.firstname,
            lastname: decoded.lastname
        }

        next();
    })
})

io.on('connection', (socket) => {
    console.log('Connected user ' + socket.user.login)
    socket.emit('conn', socket.user.login)
})

let usersInQueue = [];

app.post('/register', async (req, res) => {
    try {
        const {firstname, lastname, login, password} = req.body;
        const hashedPassword = await bcrypt.hash(password, 8);
        
        const isInDatabase = (login) => {
            return new Promise((resolve, reject) => {
                connection.query("SELECT * FROM users WHERE login=?", [login], (err, result, fields) => {
                    if(err) reject(err)
                    resolve(result)
                })
            })
        }

        const result = await isInDatabase(login);
        console.log(result)
        if(result.length == 0) {
            connection.query("INSERT INTO users(firstname, lastname, login, passwd) VALUES (?, ?, ?, ?)", [firstname, lastname, login, hashedPassword], (err, result, fields) => {
                if(err) return res.status(500).send(err)
                console.log("Dodano nowego użytkownika do bazy");
                return res.status(200).send("Dodano nowego użytkownika do bazy");
            })
        } else {
            res.status(200).send("Użytkownik jest już w bazie danych");
        }
    } catch(error) {
        res.status(501).send(error);
    }
})

app.get("/example", (req, res) => {
    res.status(200).send("Hello world")
})

app.post('/login', async (req, res) => {
    try {
        const {login, password} = req.body;
        
        const isThisUserExist = (login) => {
            return new Promise((resolve, reject) => {
                connection.query("SELECT * FROM users WHERE login=?", [login], (err, result, fields) => {
                    if(err) reject(err)
                    resolve(result)
                })
            })
        } 

        const isPasswordValid = async (passwordFromReq, passwordFromDatabase) => {
            try {
                const isMatch = await bcrypt.compare(passwordFromReq, passwordFromDatabase);
                return isMatch;
            } catch (error) {
                throw error
            }
        }

        const result = await isThisUserExist(login)
        if(result.length > 0) {
            const passwordFromDatabase = result[0].passwd;
            const isPasswordCorrect = await isPasswordValid(password, passwordFromDatabase)
            if(isPasswordCorrect) {
                const user = {
                    firstname: result[0].firstname,
                    lastname: result[0].lastname,
                    login: result[0].login,
                }
                
                const accessToken = jwt.sign(user, process.env.SECRET_KEY);
                
                return res.status(200).send({
                    accessToken: accessToken,
                    login: result[0].login,
                    firstname: result[0].firstname,
                    lastname: result[0].lastname,
                })

            } else {
                return res.status(500).send("Login lub Hasło jest niepoprawne")
            }
        } else {
            return res.status(500).send("Nie ma takiego użytkownika")
        }

    } catch (error) {
        res.status(500).send(error)
    }
})

app.post('/joinQueue', authToken, (req, res) => {
    const {user} = req.body;
    if(usersInQueue.length > 0) {
        const partner = usersInQueue.pop();
        
        const socketPartner = findSocketIdByLogin(partner)
        const mySocketId = findSocketIdByLogin(user);
    
        // console.log(socketPartner, mySocketId)
        io.to(socketPartner).emit('findPartner', {info: "znaleziono partnera", partner: user})
        io.to(mySocketId).emit('findPartner', {info: "znaleziono partnera", partner: partner})
    } else {
        usersInQueue.push(user)
    }
    // console.log(usersInQueue)
    res.status(200).send(req.body)
})

app.post('/leaveQueue', authToken, (req, res) => {
    const {user} = req.body;
    if(usersInQueue.length > 0) {
        const usersInQueueWithotMe = usersInQueue.filter(userInQueue => userInQueue !== user);
        usersInQueue = usersInQueueWithotMe;
        // console.log(usersInQueue)
        res.status(200).send("ok")
    } else {
        res.status(500).send("error")
    }
}) 

app.post('/sendMessage', authToken, async (req, res) => {
    try{
        const {message, partner} = req.body;
        const user = req.user.login;
    
        const userSocketId = await findSocketIdByLogin(user);
        const partnerSocketId = await findSocketIdByLogin(partner);
    
        const data =  { message: message, sender: user, reciver: partner}
    
        io.to(userSocketId).to(partnerSocketId).emit('message',  { message: message, sender: user});
    
        res.status(200).send(data)
    } catch (error) {
        res.status(500).send(error)
    }
})

app.post('/leaveChat', authToken, async (req, res) => {
    try {
        const {userLeave, partner} = req.body;   
        const socketPartner = findSocketIdByLogin(partner);
        io.to(socketPartner).emit('userLeaveChat', {info: `Użytkownik ${userLeave} wyszedł z czatu :(`})
    } catch (error) {
        res.status(500).send(error)
    }
})

server.listen(4000, () => {
    console.log("Server działa na porcie 4000")
})
