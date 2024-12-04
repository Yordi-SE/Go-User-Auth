"use client";

import { useSession } from "next-auth/react";
import Image from "next/image";
import { useRouter } from "next/navigation";

const HomePage = () => {
  const router = useRouter();
  const { data: session, status } = useSession();
  console.log(session);
  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center">
      {status == "loading" ? (
        // Loading State
        <div className="flex flex-col items-center">
          <div className="loader animate-spin rounded-full border-t-4 border-indigo-600 border-solid h-16 w-16"></div>
          <p className="mt-4 text-gray-700">Loading your session...</p>
        </div>
      ) : (
        // Session Loaded
        <div className="bg-white shadow-lg rounded-lg p-8 max-w-md w-full text-center">
          <div className="mb-6">
            <Image
              src={session.user?.profile_image || "/default-avatar.png"}
              width={100}
              height={100}
              alt="User Avatar"
              className="rounded-full mx-auto"
            />
          </div>
          <h1 className="text-2xl font-bold text-gray-800">
            Welcome, {session.user?.full_name || "User"}!
          </h1>
          <p className="text-gray-600 mt-2">
            You're successfully logged in. Explore your account or manage your
            preferences.
          </p>
          <div className="mt-6">
            <button className="w-full bg-indigo-600 text-white py-2 px-4 rounded-md hover:bg-indigo-700 transition">
              View Dashboard
            </button>
            <button
              onClick={() => {
                router.push("/auth/logout");
              }}
              className="w-full bg-gray-100 text-gray-800 py-2 px-4 rounded-md mt-4 hover:bg-gray-200 transition"
            >
              Logout
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default HomePage;
