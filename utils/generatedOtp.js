const generatedOtp = async () => {
  return Math.floor(Math.random() * 900000);
};

export default generatedOtp;
