import { createBrowserRouter } from 'react-router-dom';
import RootLayout from '../layouts/Rootlayout';
import App from '../App';
import User from '../pages/User';
import AuthPage from '../pages/AuthPage';
import AcceptInvitation from '../pages/AcceptInvitation';
import SharePage from '../pages/SharePage';
import MfaSetup from '../pages/MfaSetup';
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
    },
    {
        path:"auth/mfa-setup",
        element:<MfaSetup/>
    },
    {
        path:"guest/accept",
        element:<AcceptInvitation/>
    },
    {
        path:"share",
        element:<SharePage/>
    },
    ]
}]);

export default router
