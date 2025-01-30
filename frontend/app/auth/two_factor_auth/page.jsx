"use client"

import { useState, useRef, Suspense,  } from "react"
import { Button } from "../components/ui/button"
import axios from "axios"
import { useSearchParams } from "next/navigation";
import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";


function OTPPage() {
  const searchParams = useSearchParams();
  const router = useRouter()
  const [otp, setOtp] = useState(["", "", "", "", "", ""])
  const inputRefs = [
    useRef(null),
    useRef(null),
    useRef(null),
    useRef(null),
    useRef(null),
    useRef(null),
  ]

  const email = searchParams.get("email")
  const otp_token = searchParams.get("otp_token")
  const handleChange = (index, value) => {
    if (value.length > 1) {
      value = value.slice(0, 1)
    }
    const newOtp = [...otp]
    newOtp[index] = value
    setOtp(newOtp)

    if (value !== "" && index < 5) {
      inputRefs[index + 1].current?.focus()
    }
  }

  const handleKeyDown = (index, e) => {
    if (e.key === "Backspace" && otp[index] === "" && index > 0) {
      inputRefs[index - 1].current?.focus()
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    const otpString = otp.join("")
    try {
      const response = await axios.post(`${process.env.NEXT_PUBLIC_API_BASE_URL}/api/auth/user/Two_factor_auth?otp_token=${otp_token}`, { otp_code: otpString, email: email })
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
        two_factor_auth: user.two_factor_auth,
        redirect: false,
      });
      router.push("/");

    }
    catch (error) {
      console.log(error)
    }
    console.log("Submitted OTP:", otpString)
    // Here you would typically send the OTP to your server for verification
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="bg-white p-8 rounded-lg shadow-md w-96">
        <h1 className="text-2xl font-bold mb-6 text-center">Enter OTP</h1>
        <form onSubmit={handleSubmit}>
          <div className="flex justify-between mb-6">
            {otp.map((digit, index) => (
              <input
                key={index}
                type="text"
                inputMode="numeric"
                maxLength={1}
                value={digit}
                onChange={(e) => handleChange(index, e.target.value)}
                onKeyDown={(e) => handleKeyDown(index, e)}
                ref={inputRefs[index]}
                className="w-12 h-12 text-center text-2xl border rounded-md focus:outline-none focus:border-blue-500"
              />
            ))}
          </div>
          <Button type="submit" className="w-full">
            Verify OTP
          </Button>
        </form>
      </div>
    </div>
  )
}

export default function OTP() {
 return (
  <Suspense fallback="Loading...">
    <OTPPage />
  </Suspense>
 )
}