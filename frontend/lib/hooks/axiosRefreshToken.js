"use client";

import axiosInst from "../axios";
import axios from "axios";
import { signIn, useSession, signOut } from "next-auth/react";

export const useRefreshToken = () => {
  const { data: session } = useSession();

  const refreshToken = async () => {
    try {
      const res = await axiosInst.get("/api/auth/user/refresh", {
        withCredentials: true,
      });

      if (!session) signIn();
    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (error.response?.status === 401) {
          signOut({
            callbackUrl: "/auth/login",
            redirect: false,
          });
          alert("Session expired. Please log in again.");
        } else {
          alert(
            "An error occurred while refreshing the session. Please try again."
          );
        }
      } else {
        alert("An unexpected error occurred.");
      }
    }
  };

  return refreshToken;
};
