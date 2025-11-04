import express from "express"
import mysql from "mysql"

const app = express()

app.get("/", (req, res)=>{
    res.json("Test backend miumiu")
})
const db = mysql.createConnection({
    host:"localhost",
    user:"root",
    password:"123456789",
    database:"uzytkownicy"
})

app.get("/", (req,res)=>{
    res.json("Hello tutaj backend elo melo")
})

app.get("/autorzy", (req,res)=>{
    const q = "SELECT * FROM uzytkownicy"
    db.query(q, (err, res) =>{
        if(err) return res.json(err)
        return res.json(data)

    })
})
app.listen(8800, () =>{

    console.log("Connected supi brawo!!")
})

fetch('http://localhost:3000/api/auth/logout',{method:'POST',credentials:'include'})
  .then(()=>location.reload());
  
fetch('http://localhost:3000/api/auth/me',{credentials:'include'})
  .then(r=>r.ok?r.json():null).then(d=>console.log(d?.user));
