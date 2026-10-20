import React from 'react'
import { createBrowserRouter } from 'react-router-dom';
import RootLayout from '../layouts/Rootlayout';
import App from '../App';
import User from '../pages/User';
import AuthPage from '../pages/AuthPage';
const router = createBrowserRouter([{
    path:"/",
    element: <RootLayout/>,
    children:[
    {
        index:true,
        element: <App/>
    },
    {
        path:"dashboard",
        element:<User/>
    },
    {
        path:"auth/login",
        element:<AuthPage/>
    }
    ]
}]);

export default router
