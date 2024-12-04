"use client";
import axios from "@/lib/axios";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Loading from "./loading";

export default function Page() {
  const params = useParams();
  const [isResending, setIsResending] = useState(false);
  const [message, setMessage] = useState("");
  const [verificationStatus, setVerificationStatus] = useState("loading");
  const keys = params.key;
  const key = keys ? decodeURIComponent(keys) : "";

  const [email, setEmail] = useState("");
  useEffect(() => {
    async function verifyUsers(token) {
      const verificationStatuss = await verifyUser(token);
      setVerificationStatus(verificationStatuss);
    }
    verifyUsers(key);
  }, []);
  const handleResendEmail = async () => {
    setIsResending(true);
    setMessage("");

    // Simulate an API call to resend the verification email

    try {
      await axios.post(`/api/auth/user/resend_verification`, {
        email: email,
      });
      setMessage("Verification email has been resent successfully.");
    } catch (error) {
      setMessage("Failed to resend email. Please try again later.");
    } finally {
      setIsResending(false);
    }
  };
  if (!key) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100">
        <div className="max-w-md w-full bg-white p-6 rounded shadow-md text-center">
          <div>
            <h1 className="text-2xl font-bold text-red-500">
              Verification Failed
            </h1>
            <p className="text-gray-600 mt-4">
              The verification link may be invalid or expired.
            </p>
            {
              // input for user to enter email
            }
            <input
              type="email"
              className="mt-4 w-full px-4 py-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
              placeholder="Enter your email"
              onChange={(e) => setEmail(e.target.value)}
            />
            <button
              onClick={handleResendEmail}
              disabled={isResending}
              className={`mt-6 w-full px-4 py-2 text-white font-semibold rounded ${
                isResending
                  ? "bg-gray-400"
                  : "bg-indigo-600 hover:bg-indigo-700"
              } focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2`}
            >
              {isResending ? "Resending..." : "Resend Email"}
            </button>
            {message && (
              <p className="mt-4 text-sm text-green-600">{message}</p>
            )}
          </div>
        </div>
      </div>
    );
  }
  //simulate a delay of 10 seconds

  return (
    <>
      {verificationStatus == "loading" ? (
        <Loading />
      ) : (
        <div className="min-h-screen flex items-center justify-center bg-gray-100">
          <div className="max-w-md w-full bg-white p-6 rounded shadow-md text-center">
            {verificationStatus === "success" && (
              <div>
                <h1 className="text-2xl font-bold text-green-500">
                  Email Verified!
                </h1>
                <p className="text-gray-600 mt-4">
                  Your account has been successfully verified.
                </p>
                <a
                  href="/auth/login"
                  className="mt-6 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 inline-block"
                >
                  Go to Login
                </a>
              </div>
            )}
            {verificationStatus == "error" && (
              <div>
                <h1 className="text-2xl font-bold text-red-500">
                  Verification Failed
                </h1>
                <p className="text-gray-600 mt-4">
                  The verification link may be invalid or expired.
                </p>
                {
                  // input for user to enter email
                }
                <input
                  type="email"
                  className="mt-4 w-full px-4 py-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
                  placeholder="Enter your email"
                  onChange={(e) => {
                    e.preventDefault();

                    function validateEmail(email) {
                      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                      return emailRegex.test(email);
                    }
                    if (validateEmail(e.target.value)) {
                      setEmail(e.target.value);
                    } else {
                      setEmail("");
                    }
                  }}
                />
                <button
                  onClick={handleResendEmail}
                  disabled={isResending || !email}
                  className={`mt-6 w-full px-4 py-2 text-white font-semibold rounded ${
                    isResending || email !== ""
                      ? " bg-indigo-600 hover:bg-indigo-700 "
                      : " bg-gray-300 text-gray-50 "
                  } focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 `}
                >
                  {isResending ? "Resending..." : "Resend Verification"}
                </button>
                {message && (
                  <p className="mt-4 text-sm text-green-600">{message}</p>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}

async function verifyUser(token) {
  try {
    const response = await axios.post("/api/auth/user/verify_email", {
      key: token,
    });
    return response.status === 200 ? "success" : "error";
  } catch (error) {
    return "error";
  }
}
