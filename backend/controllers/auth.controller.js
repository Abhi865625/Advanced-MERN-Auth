import bcryptjs from "bcryptjs";
import crypto, { hash } from "crypto";

import {User} from "../models/user.model.js"
import {generateTokenAndSetCookie} from "../utils/generateTokenAndSetCookie.js"
import { sendVerificationEmail, sendWelcomeEmail, sendPasswordResetEmail, sendResetSuccessEmail } from "../mailtrap/emails.js";


export const signup = async (req,res)=>{
    const {email, password, name} = req.body;
    try {
        if(!email || !password || !name){
            throw new Error("All fields are required");   
        }

        const userAlreadyExists = await User.findOne({email});
        if(userAlreadyExists){
            return res.status(400).json({success:false, message: "User already exists"})    
        }

        const hashedPassword = await bcryptjs.hash(password,10);
        const verificationToken = Math.floor(100000 + Math.random() * 900000).toString();
        const user = new User({
            email,
            password: hashedPassword,
            name,
            verificationToken,
            verificationTokenExpiresAt: Date.now() + 24*60*60*1000 //24hours
        })

        await user.save();

        // jwt
        generateTokenAndSetCookie(res,user._id);


        // Send verification email asynchronously
        sendVerificationEmail(user.email, verificationToken).catch(error => {
            console.error("Error sending verification email:", error);
        });

        return res.status(201).json({
            success:true, 
            message: "User created successfully",
            user:{
                ...user._doc,
                password:undefined,
            }
        }) 


    } catch (error) {
        return res.status(400).json({success:false, message: error.message})
    }
}

export const verifyEmail = async (req,res)=>{
    const {code} =  req.body;

    try {
        const user = await User.findOne({
            verificationToken:code,
            verificationTokenExpiresAt:{$gt:Date.now()}
        })

        if(!user){
            return res.status(400).json({
               success: false,
               message:"Invalid or expired verification code" 
            })
        }

        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpiresAt = undefined;

        await user.save();

        await sendWelcomeEmail(user.email, user.name)

        return res.status(200).json({
            success: true,
            message:"Email verified successfully",
             user:{
                ...user._doc,
                password:undefined,
             }
         })

    } catch (error) {
        console.log("error in verifyEmail",error);
        
        return res.status(500).json({
            success: false,
            message:"server error"
         })
        
    }
}

export const login = async (req,res)=>{
    const {email, password} = req.body;

    try {
        if(!email || !password){
            throw new Error("All fields are required");   
        }
        const user = await User.findOne({email});
        
        if(!user){
            return res.status(400).json({success:false, message: "Invalid credentials"})    
        }

        const isPasswordValid = await bcryptjs.compare(password, user.password) ;

        if(!isPasswordValid){
            return res.status(400).json({success:false, message: "Invalid credentials"})    
        }

        generateTokenAndSetCookie(res, user._id);

        user.lastlogin = new Date();
        await user.save();

        return res.status(200).json({
            success: true,
            message:"logged in successfully",
             user:{
                ...user._doc,
                password:undefined,
             }
         })
        
    } catch (error) {
        console.log("Error in login", error);
        return res.status(400).json({success:false, message: error.message}) 
    }
}

export const logout = async (req,res)=>{
    res.clearCookie("token");
    return res.status(200).json({
        success: true,
        message:"Logged out successfully",
     })
}


export const forgotPassword = async (req,res)=>{
    const {email} = req.body;
    try {
        if(!email){
            throw new Error("All fields are required");   
        }
        const user = await User.findOne({email});
        
        if(!user){
            return res.status(400).json({success:false, message: "Invaild email"}) 
        }

        // generate reset token
        const resetToken = crypto.randomBytes(20).toString("hex");
        const resetTokenExpiresAt  = Date.now() + 1 * 60 * 60 * 1000 ; // 1hour

        user.resetPasswordToken = resetToken;
        user.resetPasswordExpiresAt = resetTokenExpiresAt;

        await user.save();

        sendPasswordResetEmail(user.email, `${process.env.CLIENT_URL}/reset-password/${resetToken}`)

        return res.status(200).json({
            success: true,
            message:"Password reset link sent to your email",
         })
        
    } catch (error) {
        console.log("Error in forgotPassword",error);
        
        return res.status(400).json({success:false, message: error.message})   
    }
}

export const resetPassword = async (req,res)=>{
    
    try {
        const {token} = req.params;
        const {password} = req.body;

        const user = await User.findOne({resetPasswordToken: token,
            resetPasswordExpiresAt: {$gt:Date.now()}
        });

        if(!user){
            return res.status(400).json({
                success:false,
                message: "Invalid or expired reset token"
            })
        }

        //update password

        const hashedPassword = await bcryptjs.hash(password,10);

        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpiresAt = undefined;

        await user.save();

        sendResetSuccessEmail(user.email)

        return res.status(200).json({
            success: true,
            message:"Password reset successfully",
        })
        
    } catch (error) {
        console.log("Error in resetPassword",error);
        
        return res.status(400).json({success:false, message: error.message})   
    }
}

export const checkAuth = async (req,res) => {
    try {
        const user = await User.findById(req.userId).select("-password");
        if(!user){
            return res.status(400).json({success:false, message: "User not found"}) 
        }
        return res.status(200).json({
            success: true,
            user,
        })
        
    } catch (error) {
        console.log("Error in checkAuth", error);
        return res.status(400).json({
            success: false,
            message:error.message,
        })
        
        
    }
}





