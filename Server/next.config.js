/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: false,
};

module.exports = {
  env: {
    MONGO_URL:"deneme",
PORT:5000,
JWT_SECRET_KEY:"AnyKey",
HOST:"smtp.gmail.com",
SERVICE:"gmail",
EMAIL_PORT:587,
SECURE:true,
USER:"User_Email",
PASS:"User_Password",
BASE_URL:"http://localhost:5000",
FRONTEND_URL:"http://localhost:3000",
  },
 
}
