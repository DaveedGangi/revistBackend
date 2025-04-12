const express = require("express");


const app = express();
const cors = require("cors");
const cookieParser = require("cookie-parser");


app.use(express.json());
app.use(cors({origin:"http://localhost:3000",credentials:true}));
app.use(cookieParser());
require("dotenv").config();

const path = require("path");

const {open} = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const jwtToken= require("jsonwebtoken");

const SECRET_TOKEN_KEY=process.env.SECRET_TOKEN_KEY;
const REFRESH_TOKEN_KEY=process.env.REFRESH_TOKEN_KEY;
const port=process.env.PORT || 3000


const dbPath = path.join(__dirname,"revist.db");

let db;

const intializeDatabase=async()=>{

    try{
    db=await open({
        filename: dbPath,
        driver: sqlite3.Database
    });

    app.listen(port,()=>{
        console.log(`Server started on port ${port}`);
    });
    await db.run(`CREATE TABLE IF NOT EXISTS users
        (id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL)`);
    await db.run(`CREATE TABLE IF NOT EXISTS categories(
        id INTEGER PRIMARY KEY,
        title TEXT NOT NULL,
        image TEXT NOT NULL,
        category TEXT NOT NULL,
        itemCount INTEGER NOT NULL
        )`)

}
catch(err){
    console.error("Unable to connect to the database",err);
    process.exit(1);
}

}

intializeDatabase();

//user signup
app.post("/signup",async(req,resp)=>{
    try{
        const {username,password}=req.body;
      
        const existingUser=await db.get("SELECT * FROM users Where username=?",[username]);
        if(existingUser){
            resp.status(409).json({message:"user already exists"});
            return;
        }
        const hashedPassword=await bcrypt.hash(password,10);
        await db.run("INSERT INTO users (username,password) VALUES(?,?)",[username,hashedPassword]);
        resp.status(201).json({message:"user created successfully"});
    }
    catch(err){
        console.error(err);
        resp.status(500).json({message:"server error"});
    }
})


app.post("/login",async(req,resp)=>{
    try{
        const {username,password}=req.body;
        const user=await db.get("SELECT * FROM users WHERE username=?",[username]);
        if(!user){
            resp.status(401).json({message:"user not found"});
            return;
        }
        const isPasswordValid=await bcrypt.compare(password,user.password);
        if(!isPasswordValid){
            resp.status(401).json({message:"invalid password"});
            return;
        }
        const accessToken=jwtToken.sign({userId:user.id}, SECRET_TOKEN_KEY,
            {
            expiresIn:"1h"})
        const refreshToken=jwtToken.sign({userId:user.id},REFRESH_TOKEN_KEY,
            {expiresIn:"7d"})


        resp.cookie("accessToken",accessToken,{httpOnly:true,
            secure:false,sameSite:"Lax",maxAge:60*60*1000})
        .cookie("refreshToken",refreshToken,{httpOnly:true,
            secure:false,sameSite:"Lax",maxAge:7*24*60*60*1000})
        .json({message:"login successfull"});
    }
    catch(err){
        console.error(err);
        resp.status(500).json({message:"server error"});
    }
})

app.post("/refresh-token",async(req,resp)=>{
    const {refreshToken}=req.cookies;
    if(!refreshToken){
        return resp.sendStatus(401);
    }
    try{
        const user=jwtToken.verify(refreshToken,REFRESH_TOKEN_KEY);
        const newAccessToken=jwtToken.sign({userId:user.id},SECRET_TOKEN_KEY,{expiresIn:"1h"})
        resp.cookie("accessToken",newAccessToken,{
            httpOnly:true,
            secure:false,
            sameSite:"Lax",maxAge:60*60*1000
        })
        .json({message:"Token refreshed"})
    }
    catch{
        resp.sendStatus(403);
    }

})

app.post("/logout",async(req,resp)=>{
    resp.clearCookie("accessToken");
    resp.clearCookie("refreshToken");
    resp.json({message:"logged out"});

})

const authenticate=(req,resp,next)=>{
    const{accessToken}=req.cookies;
    if(!accessToken){
        return resp.sendStatus(401);
    }
    try{
        const decoded=jwtToken.verify(accessToken,SECRET_TOKEN_KEY);
        req.userId=decoded.userId;
        next()
    }
    catch(err){
        console.log("Token verification faild",err);
        resp.sendStatus(403);
    }
}

app.get("/protected",authenticate,async(req,resp)=>{
    const userRow=await db.get("SELECT username FROM users WHERE id=?",[req.userId])
    if(userRow){
        resp.json({message:"user authenticated successfully",username:userRow.username})
    }
    else{
        resp.json({message:"user not authenticated"})
    }
})

app.post("/addcategory",authenticate,async(req,resp)=>{
    const{title,image,category,itemCount}=req.body 
  
    try{
        if(!title ||!image ||!category || typeof itemCount!=="number"){
            return resp.status(400).json({message:"invalid input"})
        }
        
    await db.run("INSERT INTO categories(title,image,category,itemCount) VALUES(?,?,?,?)",[title,image,category,itemCount]);

        resp.status(200).json({message:"category added successfully"});

    }
    catch{
        resp.status(500).json({message:"server error"});
    }


})

app.get("/allcategory",authenticate,async(req,resp)=>{
    try{
        const allcategoryproducts=await db.all(`SELECT * FROM categories`);
        resp.json({categories:allcategoryproducts})
    }
    catch{
        resp.json({message:servererror});
    }
})

app.put("/editcategory/:id",authenticate,async(req,resp)=>{

    const{title,image,category,itemCount}=req.body
    const{id}=req.params
  
    
    try{
        if(!title ||!image ||!category || typeof itemCount!=="number"){
            return resp.status(400).json({message:"invalid input"})
        }
        const getCategory=await db.get("SELECT * FROM categories WHERE id=?",[id])
        if(!getCategory){
            resp.status(404).json({message:"Category not found"})
        }

        await db.run("UPDATE categories SET title=?,image=?,category=?,itemCount=? WHERE id=?",[title,image,category,itemCount,id]);
    
            resp.status(200).json({message:"category updated successfully"});
    
        }
        catch{
            resp.status(500).json({message:"server error"});
        }

})

app.delete("/deletecategory/:id",authenticate,async(req,resp)=>{
    const{id}=req.params;
   
    try{
        const getCategory=await db.get("SELECT * FROM categories WHERE id=?",[id])
        if(!getCategory){
            resp.status(404).json({message:"Category not found"})
        }
        await db.run("DELETE FROM categories WHERE id=?",[id])
        resp.status(200).json({message:"Category deleted successfully"});
    }
    catch{
        resp.status(500).json({message:"unable to delete category"})
    }
})



