import { error } from "console";
import userModel from "../models/user.model.js";
import bycryptjs from "bcryptjs";
import sendEmail from "../config/sendEmail.js";
import verifyEmailTemplate from "../utils/verifyEmailTemplate.js";
import generateAccessToken from "../utils/generateAccessToken.js";
import generateRefreshToken from "../utils/generateRefreshToken.js";
import uploadImageCloudinary from "../utils/uploadImageCloudinary.js";

export async function registerUserController(request, response) {
  try {
    const { name, email, password } = request.body;

    if (!name || !email || !password) {
      return response.status(400).json({
        message: "provide name , email and password",
        error: true,
        success: false,
      });
    }

    const user = await userModel.findOne({ email });

    if (user) {
      return response.json({
        message: "Email in use",
        error: true,
        success: false,
      });
    }

    const salt = await bycryptjs.genSalt(10);
    const hashPassword = await bycryptjs.hash(password, salt);

    const payload = {
      name,
      email,
      password: hashPassword,
    };

    const newUser = new userModel(payload);
    const save = await newUser.save();
    const verifyEmailUrl = `${process.env.FRONTEND_URL}/verify-email?code=${save?._id}`;
    const verifyEmail = await sendEmail({
      sendTo: email,
      subject: "verify email from binkeyit",
      html: verifyEmailTemplate({
        name,
        url: verifyEmailUrl,
      }),
    });

    return response.json({
      message: "User registered successfully",
      error: false,
      success: true,
      data: save,
    });
  } catch (error) {
    return response.status(500).json({
      message: error.message || error,
      error: true,
      success: false,
    });
  }
}

export async function verifyEmailController(request, response) {
  try {
    const { code } = request.body;

    const user = await userModel.findOne({ _id: code });
    if (!user) {
      return response.status(400).json({
        message: "invalid code",
        error: true,
        success: false,
      });
    }

    const updatedUser = await userModel.updateOne(
      { _id: code },
      { verify_email: true }
    );

    return response.json({
      message: "email verification complete",
      success: true,
      error: false,
    });
  } catch (error) {
    return response.status(500).json({
      message: error.message,
      error: true,
      success: true,
    });
  }
}

export async function loginController(request, response) {
  try {
    const { email, password } = request.body;

    if (!email || !password) {
      return response.status(400).json({
        message: "provide email and password",
        error: true,
        success: false,
      });
    }

    const user = await userModel.findOne({ email });

    if (!user) {
      return response.status(400).json({
        message: "user not registered",
        error: true,
        success: false,
      });
    }
    if (user.status !== "Active") {
      response.status(400).json({
        message: "contact to admin",
        error: true,
        success: false,
      });
    }

    const checkPassword = await bycryptjs.compare(password, user.password);

    if (!checkPassword) {
      return response.status(400).json({
        message: "check your password",
        error: true,
        success: false,
      });
    }

    const accessToken = await generateAccessToken(user._id);
    const refreshToken = await generateRefreshToken(user._id);

    const cookiesOption = {
      httpOnly: true,
      secure: true,
      semSite: "None",
    };
    response.cookie("accessToken", accessToken, cookiesOption);
    response.cookie("refreshToken", refreshToken, cookiesOption);

    return response.json({
      message: "logged in successfully",
      error: false,
      success: true,
      data: {
        accessToken,
        refreshToken,
      },
    });
  } catch (error) {
    return response.status(500).json({
      message: error.message || error,
      error: true,
      success: false,
    });
  }
}

export async function logoutController(request, response) {
  try {
    const userId = request.userId;

    const cookiesOption = {
      httpOnly: true,
      secure: true,
      semSite: "None",
    };
    response.clearCookie("accessToken", cookiesOption);
    response.clearCookie("refreshToken", cookiesOption);

    const removeRefreshToken = await userModel.findByIdAndUpdate(userId, {
      refresh_token: "",
    });

    return response.json({
      message: "logged out successfully",
      error: false,
      success: true,
    });
  } catch (error) {
    return response.status(500).json({
      message: error.message || error,
      error: true,
      success: false,
    });
  }
}

export async function uploadAvatar(request, response) {
  try {
    const userId = request.userId;
    const image = request.file;

    const upload = await uploadImageCloudinary(image);

    const updateUser = await userModel.findByIdAndUpdate(userId, {
      avatar: upload.url,
    });

    return response.json({
      message: "upload profile",
      data: {
        _id: userId,
        avatar: upload.url,
      },
    });
  } catch (error) {
    return response.status(500).json({
      message: error.message || error,
      error: true,
      success: false,
    });
  }
}
