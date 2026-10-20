import React from 'react'
import { Link } from 'react-router-dom'
const AdminView = () => {
  return (
    <div>
      <section className="relative overflow-hidden bg-white font-sans">
        <div className='h-screen w-screen'>
            <div className='w-2/10 h-full bg-[#171440] flex p-5 justify-between flex-col text-white'>
                <div className=''>
                  <a href="#" className="flex items-center space-x-2 text-xl font-bold tracking-tight">
                  <img src="src/assets/logo.png" alt="TrustVaultLogo" className="flex items-center justify-center w-8 h-8 rounded-lg"/>
                <span className="text-xl text-white">TrustVault</span>
              </a>
                </div>
                <li className='flex flex-col gap-5'>
               <Link>Dashboard</Link> 
               <Link>Document Logs</Link>
               <Link>User & Role Setting</Link>
               <Link>Security & Auditing</Link>
               <Link>Settings</Link>
                </li>
                <div>
                    LogOut
                </div>
            </div>
            <div className='w-8/10'>

            </div>
        </div>
      </section>
    </div>
  )
}

export default AdminView
