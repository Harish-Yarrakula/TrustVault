import { createBrowserRouter } from 'react-router-dom';
import RootLayout from '../layouts/Rootlayout';
import App from '../App';
import User from '../pages/User';
import AuthPage from '../pages/AuthPage';
import AcceptInvitation from '../pages/AcceptInvitation';
import SharePage from '../pages/SharePage';
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
        path:"guest/accept",
        element:<AcceptInvitation/>
    },
    {
        path:"share/:token",
        element:<SharePage/>
    }
    ]
}]);

export default router
