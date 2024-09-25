import mysql from "mysql"
import dotenv from "dotenv"

dotenv.config()

export const connection = mysql.createConnection({
    host: process.env.HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWD,
    database: process.env.DB_NAME
})