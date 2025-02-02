import React from "react";

const EmailVerified = () => {
  return (
    <div className="flex justify-center items-center min-h-screen bg-[#f0f9f4]">
      <div className="max-w-lg w-full bg-white rounded-2xl shadow-lg p-8 text-center">
        <div className="text-4xl font-bold text-[#28a745] mb-4">🎉 Email Verified!</div>
        <p className="text-lg text-gray-700 mb-6">
          Thank you for verifying your email address. You can now access all our features.
        </p>
        <div className="mt-6">
          <a
            href="/auth/login"
            className="inline-block px-5 py-3 bg-[#28a745] text-white rounded-md text-sm font-medium transition-colors duration-300 hover:bg-[#218838]"
          >
            Login
          </a>
        </div>
      </div>
    </div>
  );
};

export default EmailVerified;
