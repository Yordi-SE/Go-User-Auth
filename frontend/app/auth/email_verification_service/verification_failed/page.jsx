import React from "react";

const VerificationFailed = () => {
  return (
    <div className="flex justify-center items-center min-h-screen bg-[#fff5f5]">
      <div className="max-w-lg w-full bg-white rounded-2xl shadow-lg p-8 text-center">
        <div className="text-4xl font-bold text-[#dc3545] mb-4">⚠️ Verification Failed</div>
        <p className="text-lg text-gray-700 mb-6">
          We couldn&apos;t verify your email address. The link may have expired or is invalid.
        </p>
        <div className="mt-6">
          <a
            href="/auth/email_verification_service"
            className="inline-block px-5 py-3 bg-[#dc3545] text-white rounded-md text-sm font-medium transition-colors duration-300 hover:bg-[#c82333]"
          >
            Resend Verification Email
          </a>
        </div>
      </div>
    </div>
  );
};

export default VerificationFailed;
