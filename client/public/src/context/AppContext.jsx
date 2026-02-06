import { createContext, useEffect, useState } from "react";
import axios from "axios";

export const AppContext = createContext()

export const AppContextprovider =(props)=>{

    axios.defaults.withCredentials=true //for cookies if not kept for ewvery refresh you have to login
   
    const backendUrl=import.meta.env.VITE_BACKEND_URL
    const [isLoggedin,setIsLoggedIn]=useState(false)
    const [userData,setUserData]=useState(false)

    const getAuthState=async()=>{
        try{
           const {data} = await axios.get(backendUrl+'/api/auth/is-auth')
           if(data.success){
            setIsLoggedIn(true)
            getUserData()
           }
        }
        catch(error){
            toast.error(error.message)
        }
    }

    const getUserData=async()=>{
        try{
          const {data} = await axios.get(backendUrl+'/api/user/data')
          data.success ? setUserData(data.userData) :toast.error(data.message)
        }
        catch(error){
           toast.error(data.message)
        }
    }
   
    useEffect(()=>{
        getAuthState();
    })

    const value = {
        backendUrl,
        isLoggedin,setIsLoggedIn,
        userData,setUserData,
        getUserData
    }

    return (
        <AppContext.Provider value={value}>
            {props.children}
        </AppContext.Provider>
    )
}