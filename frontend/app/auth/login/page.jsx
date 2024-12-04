// app/signin/page.js
"use client";

import axios from "axios";
import { signIn } from "next-auth/react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

export default function SignIn({ searchParams }) {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isResending, setIsResending] = useState(false);
  const [verifyBtnVisibilty, setVerifyBtnVisibilitY] = useState(false);
  const [message, setMessage] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const togglePasswordVisibility = () => {
    setShowPassword((prev) => !prev);
  };
  const handleResendEmail = async () => {
    setIsResending(true);
    setMessage("");

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
      router.push("/auth/email_verification_service");
    } catch (error) {
      setMessage("Failed to resend email. Please try again later.");
    } finally {
      setIsResending(false);
    }
  };
  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    const result = await signIn("credentials", {
      redirect: false,
      email,
      password,
    });

    setIsLoading(false);

    if (result?.ok) {
      window.location.href = "/";
    } else {
      if (result?.error == "Email address is not verified.") {
        setVerifyBtnVisibilitY(true);
      }
      setError(result?.error || "An unexpected error occurred.");
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <div className="w-full max-w-md p-8 space-y-4 bg-white rounded-lg shadow-lg">
        <h2 className="text-2xl font-bold text-center text-gray-800">
          Sign In
        </h2>

        {error && <p className="text-red-500 text-center">{error}</p>}
        {verifyBtnVisibilty && (
          <button
            onClick={handleResendEmail}
            disabled={isResending}
            className={`mt-6 w-full px-4 py-2 text-white font-semibold rounded ${
              isResending ? "bg-gray-400" : "bg-indigo-600 hover:bg-indigo-700"
            } focus:outline-no`}
          >
            {isResending ? "Sending Email..." : "Verify Email"}
          </button>
        )}
        {message && <p className="mt-4 text-sm text-green-600">{message}</p>}
        {searchParams?.message && (
          <p className="text-red-700 bg-red-100 py-2 px-5 rounded-md">
            {searchParams?.message}
          </p>
        )}
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700">
              Email
            </label>
            <input
              type="email"
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
              placeholder="Email"
              required
              className="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">
              Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                onChange={(e) => {
                  e.preventDefault();

                  function validatePassword(value) {
                    if (!/[A-Z]/.test(value)) {
                      return false;
                    }

                    if (!/[a-z]/.test(value)) {
                      return false;
                    }
                    if (!/[0-9]/.test(value)) {
                      return false;
                    }
                    if (!/[!@#$%^&*(),.?":{}|<>]/.test(value)) {
                      return false;
                    }
                    return true;
                  }
                  if (validatePassword(e.target.value)) {
                    setPassword(e.target.value);
                  } else {
                    setPassword("");
                  }
                }}
                placeholder="Password"
                required
                className="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
              />
              <button
                type="button"
                onClick={togglePasswordVisibility}
                className="absolute inset-y-0 right-3 flex items-center text-gray-500"
              >
                {showPassword ? (
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    viewBox="0 0 24 24"
                    fill="currentColor"
                    className="w-5 h-5"
                  >
                    <path d="M12 5C7.5 5 3.8 8.4 2 12c1.8 3.6 5.5 7 10 7s8.2-3.4 10-7c-1.8-3.6-5.5-7-10-7zm0 11a4 4 0 110-8 4 4 0 010 8zm0-6.5a2.5 2.5 0 100 5 2.5 2.5 0 000-5z" />
                  </svg>
                ) : (
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    viewBox="0 0 24 24"
                    fill="currentColor"
                    className="w-5 h-5"
                  >
                    <path d="M12 5c4.5 0 8.2 3.4 10 7a13.5 13.5 0 01-3.4 4.5l-1.5-1.5A10.6 10.6 0 0020 12c-1.8-3.6-5.5-7-10-7a9.4 9.4 0 00-2 .3L7.4 5.7A13.4 13.4 0 0112 5zm-4.8 1.5l-1.6-1.6-1.4 1.4 1.4 1.4c-1.1 1-2 2.3-2.7 3.6 1.8 3.6 5.5 7 10 7 1.6 0 3.1-.4 4.5-1l1.2 1.2 1.4-1.4-14-14zm7.5 10.3c-.6.2-1.2.2-1.7.2a7.3 7.3 0 01-6.4-4 10.5 10.5 0 012.5-3L14 14a5.7 5.7 0 01-2.3 1.3z" />
                  </svg>
                )}
              </button>
            </div>
          </div>

          <button
            type="submit"
            className={`w-full px-4 py-2 text-white rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 ${
              isLoading || !email || !password
                ? "bg-indigo-400"
                : "bg-indigo-600 hover:bg-indigo-700"
            }`}
            disabled={isLoading || !email || !password}
          >
            {isLoading ? "Signing In..." : "Sign In"}
          </button>
        </form>
        <div className="flex w-full gap-2">
          <p className="text-gray-600 text-lg">Don’t have an account?</p>
          <Link
            href={"/auth/signup"}
            className="text-accent-3 font-bold text-blue-700"
          >
            Sign Up
          </Link>
        </div>
      </div>
    </div>
  );
}
