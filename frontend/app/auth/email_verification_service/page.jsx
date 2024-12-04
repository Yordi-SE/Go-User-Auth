"use client";

import axios from "axios";
import { useSession } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

export default function VerificationSentPage() {
  const router = useRouter();
  const { data: session } = useSession();

  const [isResending, setIsResending] = useState(false);
  const [message, setMessage] = useState("");
  const [email, setEmail] = useState("");
  useEffect(() => {
    if (session) {
      router.push("/home");
    }
  }, []);
  const handleLoginRedirect = () => {
    router.push("/auth/login");
  };
  const handleResendEmail = async () => {
    setIsResending(true);
    setMessage("");

    // Simulate an API call to resend the verification email

    try {
      await axios.post(
        `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/auth/user/resend_verification`,
        {
          email: email,
        },
        {
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
      setMessage("Verification email has been resent successfully.");
    } catch (error) {
      setMessage("Failed to resend email. Please try again later.");
    } finally {
      setIsResending(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <div className="bg-white p-8 rounded-lg shadow-md max-w-md text-center">
        <h2 className="text-2xl font-semibold text-gray-800">
          Email Verification Sent
        </h2>
        <p className="mt-4 text-gray-600">
          A verification email has been sent to your registered email address.
          Please check your inbox and follow the instructions to verify your
          account.
        </p>
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
              ? "bg-indigo-600 hover:bg-indigo-700"
              : "bg-gray-300 text-gray-50"
          } focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 `}
        >
          {isResending ? "Resending..." : "Resend Verification"}
        </button>

        {message && <p className="mt-4 text-sm text-green-600">{message}</p>}

        <button
          onClick={handleLoginRedirect}
          className="mt-4 w-full px-4 py-2 text-indigo-600 font-semibold rounded border border-indigo-600 hover:bg-indigo-50 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
        >
          Log In
        </button>
      </div>
    </div>
  );
}
