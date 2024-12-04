"use client";

import axios from "axios";
import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

const AuthSuccess = () => {
  const router = useRouter();

  const handleOAuthLogin = async () => {
    try {
      const response = await axios.get(
        `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/user/validate_token`,
        {
          withCredentials: true,
        }
      );
      if (response.status !== 200) {
        throw new Error("Token validation failed");
      }

      const user = response.data;
      console.log(response.data);

      await signIn("credentials", {
        access_token: user.access_token,
        full_name: user.full_name,
        email: user.email,
        profile_image: user.profile_image,
        phone_number: user.phone_number,
        user_id: user.user_id,
        role: user.role,
        is_verified: user.is_verified,
        refresh_token: user.refresh_token,

        redirect: false,
      });

      router.push("/");
    } catch (error) {
      console.error("Error during login:", error);
      router.push("/auth/error");
    }
  };

  useEffect(() => {
    handleOAuthLogin();
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
            Authenticating, please wait...
          </p>
        </div>
      </div>
    </div>
  );
};

export default AuthSuccess;
