/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: false,
};

module.exports = {
  env: {
    NEXT_PUBLIC_BASEURL:"http://localhost:3000",
NEXT_PUBLIC_BACKENDURL:"http://localhost:5000",
  },
  nextConfig : {
    reactStrictMode: false,
  },
}
