const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const UserModel = require("../Models/User");
const nodemailer = require('nodemailer');


const signup = async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const user = await UserModel.findOne({ email });
        if (user) {
            return res.status(409)
                .json({ message: 'User is already exist, you can login', success: false });
        }
        const userModel = new UserModel({ name, email, password });
        userModel.password = await bcrypt.hash(password, 10);
        await userModel.save();
        res.status(201)
            .json({
                message: "Signup successfully",
                success: true
            })
    } catch (err) {
        res.status(500)
            .json({
                message: "Internal server errror",
                success: false
            })
    }
}


const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await UserModel.findOne({ email });
        const errorMsg = 'Auth failed email or password is wrong';
        if (!user) {
            return res.status(403)
                .json({ message: errorMsg, success: false });
        }
        const isPassEqual = await bcrypt.compare(password, user.password);
        if (!isPassEqual) {
            return res.status(403)
                .json({ message: errorMsg, success: false });
        }
        const jwtToken = jwt.sign(
            { email: user.email, _id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        )

        res.status(200)
            .json({
                message: "Login Success",
                success: true,
                jwtToken,
                email,
                name: user.name
            })
    } catch (err) {
        res.status(500)
            .json({
                message: "Internal server errror",
                success: false
            })
    }
}



// Forgot Password Function
const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        // Validate email input
        if (!email) {
            return res.status(400).json({
                message: 'Email is required.',
                success: false
            });
        }

        // Check if the user exists
        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(404).json({
                message: 'User with this email does not exist.',
                success: false
            });
        }

        // Generate a reset token with a 15-minute expiration
        const resetToken = jwt.sign(
            { _id: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '15m' }
        );

        // Construct the reset link
        const resetLink = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;

        // Configure nodemailer transporter
        const transporter = nodemailer.createTransport({
            service: 'gmail', // Use the correct email service
            auth: {
                user: process.env.EMAIL, // Sender email address
                pass: process.env.EMAIL_PASSWORD // Email password or App Password
            }
        });

        // Define the email content
        const mailOptions = {
            from: process.env.EMAIL, // Sender email
            to: user.email, // Recipient email
            subject: 'Password Reset Request',
            html: `<p>Hello ${user.name},</p>
                   <p>You requested a password reset. Click the link below to reset your password:</p>
                   <a href="${resetLink}" target="_blank">Reset Password</a>
                   <p>This link is valid for 15 minutes.</p>`
        };

        // Send the email
        await transporter.sendMail(mailOptions);

        // Respond with success
        res.status(200).json({
            message: 'Password reset link sent to your email.',
            success: true
        });
    } catch (error) {
        console.error('Error in forgotPassword:', error.message);

        // Handle specific error cases
        if (error.response) {
            console.error('Email service error:', error.response);
        }

        res.status(500).json({
            message: 'Internal server error.',
            success: false
        });
    }
};



// Reset Password Function
const resetPassword = async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        // Validate input
        if (!token || !newPassword) {
            return res.status(400).json({
                message: 'Token and new password are required.',
                success: false
            });
        }

        // Verify the reset token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Find the user based on the token's payload
        const { _id, email } = decoded;
        const user = await UserModel.findOne({ _id, email });

        if (!user) {
            return res.status(404).json({
                message: 'Invalid or expired reset token.',
                success: false
            });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the user's password
        user.password = hashedPassword;
        await user.save();

        // Respond with success
        res.status(200).json({
            message: 'Password reset successful. You can now log in with your new password.',
            success: true
        });
    } catch (error) {
        console.error('Error in resetPassword:', error.message);

        // Handle specific error cases
        if (error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                message: 'Invalid or expired reset token.',
                success: false
            });
        }

        res.status(500).json({
            message: 'Internal server error.',
            success: false
        });
    }
};
module.exports = {
    signup,
    login,
    forgotPassword,
    resetPassword
}