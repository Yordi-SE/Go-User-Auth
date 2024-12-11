"use client";

import React from "react";
import { useRouter } from "next/navigation";

const AuthError = () => {
  const router = useRouter();

  const handleRetry = () => {
    router.push("/auth/login");
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gray-100">
      <div className="bg-white p-6 rounded-lg shadow-md w-96 text-center">
        <h1 className="text-2xl font-bold text-red-500 mb-4">
          Authentication Failed
        </h1>
        <p className="text-gray-700 mb-6">
          We couldn't sign you in with Google. Please try again or use another
          method.
        </p>
        <button
          onClick={handleRetry}
          className="px-4 py-2 bg-blue-500 text-white font-semibold rounded hover:bg-blue-600 transition"
        >
          Retry Login
        </button>
        <button
          onClick={() => router.push("/support")}
          className="ml-4 px-4 py-2 bg-gray-300 text-gray-700 font-semibold rounded hover:bg-gray-400 transition"
        >
          Contact Support
        </button>
      </div>
    </div>
  );
};

export default AuthError;
