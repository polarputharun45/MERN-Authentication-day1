import bcrypt from 'bcryptjs';
import jwt from  'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';
import { EMAIL_VERIFY_TEMPLATE,PASSWORD_RESET_TEMPLATE } from '../config/emailTemplates.js';

export const register = async (req,res)=>{
    const {name,email,password}= req.body;

    if(!name || !email || !password){
        return res.json({success:false,message:'Missing Details'})
    }

    try{
       const existingUser=await userModel.findOne({email})
       if(existingUser){
         return res.json({success:false,message:"User Already Exists"});
       }
        const hashedPassword=await bcrypt.hash(password,10);

        const user = new userModel({name,email,password:hashedPassword});
        await user.save(); // new user will be saved in userModel
        
        const token = jwt.sign({id:user._id},process.env.JWT_SECRECT,{expiresIn:'7d'});

        res.cookie('token', token ,{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite:process.env.NODE_ENV ==='production' ? 'none' :'strict',
            maxAge:7 * 24 * 60 * 60 * 1000

        });

        //Sending Welcome Email
       const mailOptions={
        from:process.env.GMAIL_USER,
        to:email,
        subject:'Welcome to XXXXXX',
        text:`welcome to XXXXX website . Your Account has been created with email if ${email}`
       }

       await transporter.sendMail(mailOptions);
      return res.json({success:true});
    }  
    catch(error){
        res.json({success:false,message:error.message})
    }

    
}

////////////////////////////////////////////////////////////////
export const login = async(req,res)=>{
     const {email,password}=req.body;

     if(!email || !password){
        return res.json({success:false,message:'Email and Password are required'})
     }
     try{
       const user = await userModel.findOne({email})
       if(!user){
        return res.json({success:false,message:'Invalid email'})
       }
       const isMatch = await bcrypt.compare(password,user.password);
       if(!isMatch){
        return res.json({success:false,message:'Invalid password'})
       }

       const token = jwt.sign({id:user._id},process.env.JWT_SECRECT,{expiresIn:'7d'});

        res.cookie('token', token ,{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite:process.env.NODE_ENV ==='production' ? 'none' :'strict',
            maxAge:7 * 24 * 60 * 60 * 1000

        });

        return res.json({success:true});
      
     }
     catch(error){
       return res.json({success:false, message:error.message})
     }
}

////////////////////////////////////////////////////////////////

export const logout= async(req,res)=>{
  try{
     res.clearCookie('token',{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite:process.env.NODE_ENV ==='production' ? 'none' :'strict',
     })
     return res.json({success:true,message:"Logged Out"});
  }
  catch(error){
    return res.json({success:false,message:error.message});
  }
}

///////////////////////////////////////////////////////////////

//send verification otp to Users email
export const sendVerifyOtp = async(req,res)=>{
    try{
      const {userId}=req.body || {};

      const user = await userModel.findById(userId);

      if(user.isAccountVerified){
        return res.json({success:false,message:"Account already verified"})
      }

      const otp= String(Math.floor(100000+Math.random() * 900000));

      user.verifyOtp = otp;
      user.verifyOtpExpiredAt=Date.now()+ 24*60*60*1000

      await user.save()

      const mailOption={
        from:process.env.GMAIL_USER,
        to:user.email,
        subject:'Account Verification OTP',
        //text:`your OTP is ${otp} . Verify your account using this OTP.`
        html:EMAIL_VERIFY_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email)
        
      }

      await transporter.sendMail(mailOption);

      res.json({success:true,"message":'Verification OTP sent on registered Email'});
    }
    catch(error){
        res.json({success:false,message:error.message});
    }
} 

/////////////////////////////////////////////////////////////

export const  verifyEmail = async(req,res)=>{
    const {userId,otp}=req.body;
    if(!userId || !otp){
        return res.json({success:false,message:'Missing details'});
    }

    try{
     const user = await userModel.findById(userId);

     if(!user){
        return res.json({success:false,message:'User not found'});
     }
     if(user.verifyOtp===''|| user.verifyOtp!=otp){
        return res.json({success:false,message:'Invalid OTP'});
     }

     if(user.verifyOtpExpiredAt<Date.now()){
        return res.json({success:false,message:"OTP Expired"}); 
     }

     user.isAccountVerified=true;
     user.verifyOtp="";
     user.verifyOtpExpiredAt=0;

     await user.save();
     return res.json({success:true,message:"Email verified Successfully"});

    }
    catch(error){
       return res.json({success:false,message:error.message});
    }
}


///////////////////////////////////////////////////////////////////////

export const isAuthenticated =async(req,res)=>{
  try{
      return res.json({success:true});
  }
  catch(error){
    res.json({success:false,message:error.message});
  }
}

/////////////////////////////////////////////////////////////////////////
//send Password reset OTP

export const sendResetOtp= async(req,res)=>{
  const {email} = req.body;
  if(!email){
    return res.json({success:false,message:"Email required"})
  }
  try{
     const user=await userModel.findOne({email});
     if(!user){
      return res.json({success:false,message:"User not found"});
     }

      const otp = String(Math.floor(100000+Math.random()*900000));
      user.resetOtp=otp;
      user.resetOtpExpiredAt=Date.now()+15*60*1000

      await user.save();

      const mailOption ={
        from:process.env.GMAIL_USER,
        to:user.email,
        subject:"Password reset otp",
        //text:`Your Password Reset OTP ${otp}. use the OTP to Reset Your password.`
        html:PASSWORD_RESET_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email)
      };

      await transporter.sendMail(mailOption);
     
      return res.json({success:true,message:"OTP sent to the registered Email"})
  }
  catch(error){
    return res.json({success:false,message:error.message});
  }
}


////////////////////////////////////////////////////////////////////////////////

// Reset user Password

export const resetPassword=async(req,res)=>{
  const {email,otp,newPassword} = req.body;

  if(!email || !otp || !newPassword){
    return res.json({success:false,message:"Email,otp and new Password are required"});
  }

  try{
    
    const user = await userModel.findOne({email});
    if(!user){
      return res.json({success:false,message:"User Not found"})
    }

    if(user.resetOtp==="" || user.resetOtp!== otp){
      return res.json({success:false,message:"Invalid otp"});
    }

    if(user.resetOtpExpiredAt<Date.now()){
      return res.json({success:false,message:"OTP Expired"});
    }

    const hashedPassword=await bcrypt.hash(newPassword,10);

    user.password=hashedPassword;
    user.resetOtp="";
    user.resetOtpExpiredAt=0;

    await user.save();

    return res.json({success:true,message:"password has been reset Successfully"});
    
  }
  catch(error){
    return res.json({success:false,message:error.message});
  }
}