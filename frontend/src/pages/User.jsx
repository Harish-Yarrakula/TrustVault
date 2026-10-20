import React,{useState} from 'react'
import AdminView from './roleviews/AdminView'
import WorkspaceView from './roleviews/WorkspaceView'
const User = () => {
    const [CurrentUser,SetCurrentUser]=useState("min");
  return (
    <div>
    {
        CurrentUser=="admin"?<AdminView/>:<WorkspaceView/>
    }
    </div>
  )
}

export default User
