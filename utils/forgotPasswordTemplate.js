const forgotPasswordTemplate = (name, otp) => {
  return `
<div>
    <p>Dear ${name}</p>
    <p>You requested a password reset. Please use the following OTP code to reset your password.</p>
    <div style="background:yellow;font-size:20px">
        ${otp}
    </div>
    <p>This OTP is valid for 1 hour only. Enter this OTP in the Binkeyit website to proceed resetting your password.</p>
    <br/>
    </br>
    <p>Thanks.</p>
    <p>Binkeyit</p>
</div>

`;
};

export default forgotPasswordTemplate;
