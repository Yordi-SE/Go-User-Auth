"use client";

import axios from "axios";
import { useRouter } from "next/navigation";
import { Suspense, useEffect } from "react";
import { useSearchParams } from "next/navigation";

const VerifyEmailFunc = () => {
  const router = useRouter();
  const searchParams = useSearchParams();

  const verification_token = searchParams.get("verification_token");
  const handleEmailVerification = async () => {
    try {
      const response = await axios.get(
        `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/auth/user/verify_email?verification_token=${verification_token}`,
        {
          withCredentials: true,
        }
      );
      if (response.status !== 200) {
        throw new Error("Email validation failed");
      }

      router.push("/auth/email_verification_service/verification_success");

    } catch (error) {
      router.push("/auth/email_verification_service/verification_failed");
    }
  };

  useEffect(() => {
    handleEmailVerification();
  }, []);

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <div className="text-center">
        <div role="status">
          <svg
            className="w-12 h-12 animate-spin text-blue-500"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            ></circle>
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8v8H4z"
            ></path>
          </svg>
          <p className="mt-4 text-lg text-gray-700 font-medium">
            Verifying Email, please wait...
          </p>
        </div>
      </div>
    </div>
  );
};

function VerifyEmail() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <VerifyEmailFunc />
    </Suspense>
  );
}

export default VerifyEmail;
