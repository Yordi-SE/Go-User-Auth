"use client";

import axios from "axios";
import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import { Suspense, useEffect } from "react";
import { useSearchParams } from "next/navigation";

const AuthSuccessFunc = () => {
  const router = useRouter();
  const searchParams = useSearchParams();

  const providerToken = searchParams.get("provider_token");
  const handleOAuthLogin = async () => {
    try {
      if (!providerToken) {
        router.push("/auth/backend-provider/error");
        return;
      }
      const response = await axios.get(
        `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/auth/user/validate_token?provider_token=${providerToken}`,
        {
          withCredentials: true,
        }
      );
      if (response.status !== 200) {
        throw new Error("Token validation failed");
      }

      const user = response.data;

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
        two_factor_auth: user.two_factor_auth,
        redirect: false,
      });

      router.push("/");
    } catch (error) {
      console.error("Error during login:", error);
      router.push("/auth/backend-provider/error");
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

function AuthSuccess() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <AuthSuccessFunc />
    </Suspense>
  );
}

export default AuthSuccess;
