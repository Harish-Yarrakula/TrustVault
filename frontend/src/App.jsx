import React, { useState } from 'react'
const App = () => {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  return (
    <div >
      <section className="relative  overflow-hidden bg-white text-gray-900 font-sans ">
        {/* Decorative Background Assets */}
        <div className="pointer-events-none select-none">
          {/* Star Background Pattern */}
          <img
            className="absolute top-0 right-0 w-52 md:w-auto z-0 opacity-80"
            src="src\assets\headers\star-background-header.png"
            alt="Star background"
          />


          {/* Floating Robot Hand */}
          <img
            className="absolute top-0 right-0 -mr-10 sm:-mr-0 mt-64 md:mt-96 lg:mt-72 xl:mt-80 h-32 md:h-60 lg:h-80 z-10 animate-movement"
            src="src\assets\headers\robot-hand-header.png"
            alt="Robot hand"
          />

          {/* Fallback ambient color wash */}
          <div className="absolute top-0 right-0 w-72 h-72 md:w-96 md:h-96 bg-gradient-to-br from-orange-200/40 via-amber-100/20 to-transparent rounded-full blur-3xl z-0" />
        </div>

        <div>
      {/* Navigation Bar */}
        <nav className="relative z-20 mb-24 py-3 bg-transparent">
          <div className="container px-4 mx-auto max-w-7xl">
            <div className="flex items-center justify-between">
              {/* Logo */}
              <a href="#" className="flex items-center space-x-2 text-xl font-bold tracking-tight text-gray-900">
                  <img src="src/assets/logo.png" alt="TrustVaultLogo" className="flex items-center justify-center w-8 h-8 rounded-lg"/>
                <span className="text-xl font-black">TrustVault</span>
              </a>

              {/* Mobile Hamburger Button */}
              <div className="lg:hidden ml-auto">
                <button
                  type="button"
                  onClick={() => setMobileNavOpen(true)}
                  aria-label="Open mobile menu"
                  className="flex w-12 h-12 items-center justify-center bg-gray-100 hover:bg-gray-200 rounded-md transition duration-200 focus:outline-none focus:ring-2 focus:ring-orange-600"
                >
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <line x1="3" y1="12" x2="21" y2="12" />
                    <line x1="3" y1="6" x2="21" y2="6" />
                    <line x1="3" y1="18" x2="21" y2="18" />
                  </svg>
                </button>
              </div>

              {/* Desktop Auth CTAs */}
              <div className="hidden lg:flex items-center ml-auto">
                <a href="#" className="inline-block mr-8 text-sm font-semibold text-orange-900 hover:text-gray-900 transition-colors">
                  Sign In
                </a>
                <a
                  href="#"
                  className="relative group inline-block py-2.5 px-5 text-sm font-semibold text-orange-900 border border-gray-300 rounded-md overflow-hidden transition-colors"
                >
                  <div className="absolute inset-0 w-full h-full bg-orange-900 -translate-x-full group-hover:translate-x-0 transition-transform duration-300 ease-out" />
                  <span className="relative group-hover:text-white transition-colors duration-300">
                    Create an account
                  </span>
                </a>
              </div>
            </div>
          </div>
        </nav>
    </div>

        {/* Main Hero Body */}
        <div className="relative container px-4 mx-auto max-w-7xl z-10">
          <div className="max-w-7xl mx-auto">
            {/* Main Title */}
            <div className="max-w-4xl mx-auto text-center">
              <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-black text-gray-900 tracking-tight mb-8 sm:mb-12">
                <span>Enterprise Security you can </span>
                <span className="font-serif italic text-orange-900">Trust.</span>
              </h1>
            </div>

            {/* Subtext and Graphic Arrow */}
            <div className="md:flex items-start mb-12 max-w-2xl">
              <div className="hidden md:block mr-8 pt-3 text-orange-900 flex-shrink-0">
                <svg width="84" height="10" viewBox="0 0 84 10" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M1 4.25C0.585786 4.25 0.25 4.58579 0.25 5C0.25 5.41421 0.585786 5.75 1 5.75L1 4.25ZM84 5.00001L76.5 0.669879L76.5 9.33013L84 5.00001ZM1 5.75L77.25 5.75001L77.25 4.25001L1 4.25L1 5.75Z" fill="currentColor" />
                </svg>
              </div>
              <p className="text-lg md:text-xl text-gray-700 font-medium leading-relaxed">
                TrustVault empowers enterprises with uncompromising document security and seamless collaboration.
              </p>
            </div>

            {/* Primary CTA Button */}
            <a
              href="#"
              className="relative group inline-flex items-center justify-center w-full sm:w-auto py-4 px-8 mb-20 text-white font-semibold rounded-md bg-orange-900 overflow-hidden shadow-lg hover:shadow-orange-900/20 transition-shadow"
            >
              <div className="absolute inset-0 w-full h-full bg-gray-900 -translate-x-full group-hover:translate-x-0 transition-transform duration-300 ease-out" />
              <div className="relative flex items-center justify-center space-x-3">
                <span>Meet The Expert</span>
                <svg className="w-3.5 h-3.5 transform group-hover:translate-x-1 transition-transform" viewBox="0 0 8 12" fill="none">
                  <path d="M1.5 1.5L6.5 6L1.5 10.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>
            </a>

            {/* Stats & Social Proof Row */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
              {/* Brands Section */}
              <div className="lg:col-span-7">
                <span className="block mb-6 text-xs font-bold tracking-wider text-gray-400 uppercase">
                  Secure Sensitive Workflows across different Industries
                </span>
                <div className="flex flex-wrap items-center gap-8 opacity-60 grayscale hover:grayscale-0 transition-all w-100">
                  <img src="src\assets\industries\Gemini_Generated_Image_i3w7pli3w7pli3w7.png" alt="Industries" />
                </div>
              </div>

              {/* Metrics Card */}
              <div className="lg:col-span-5 relative">
                <div className="bg-orange-50 border border-orange-100 rounded-3xl p-6 sm:p-8 shadow-sm">
                  <h3 className="text-xl font-bold text-gray-900 mb-6">
                    We are building the future together
                  </h3>
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="block text-4xl sm:text-5xl font-black text-gray-900">SOC 2</span>
                      <span className="block text-sm font-medium text-gray-500 mt-1">Compliant Architecture</span>
                    </div>
                    <div className="h-12 w-px bg-orange-200" />
                    <div>
                      <span className="block text-4xl sm:text-5xl font-black text-gray-900">100%</span>
                      <span className="block text-sm font-medium text-gray-500 mt-1">Zero-Trust Access Enforcement</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Mobile Drawer Navigation */}
        {mobileNavOpen && (
          <div className="fixed inset-0 z-50 flex">
            {/* Backdrop */}
            <div
              className="fixed inset-0 bg-gray-900/40 backdrop-blur-sm transition-opacity"
              onClick={() => setMobileNavOpen(false)}
              aria-hidden="true"
            />

            {/* Slide-over Drawer */}
            <div className="relative flex flex-col w-5/6 max-w-sm h-full py-6 px-6 bg-white shadow-2xl z-10 overflow-y-auto">
              {/* Header / Close */}
              <div className="flex items-center justify-between mb-8">
                <a href="#" className="flex items-center space-x-2 font-bold text-lg">
                  <span className="flex items-center justify-center w-8 h-8 rounded-lg bg-orange-900 text-white font-extrabold text-lg">
                    S
                  </span>
                  <span className="font-black">TrustVault</span>
                </a>
                <button
                  type="button"
                  onClick={() => setMobileNavOpen(false)}
                  className="p-2 text-gray-500 hover:text-gray-900 rounded-lg focus:outline-none"
                  aria-label="Close menu"
                >
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>


              {/* Premium CTA */}
              <div className="py-4 px-2 mb-6 border-t border-b border-gray-100">
                <a href="#" className="flex items-center text-sm font-semibold text-orange-900 hover:text-orange-700">
                  <svg className="w-5 h-5 mr-2.5 text-amber-500" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                  </svg>
                  <span>Upgrade to Premium</span>
                </a>
              </div>

              {/* Mobile Auth Buttons */}
              <div className="space-y-3 mb-8">
                <a href="#" className="block text-center w-full py-3 px-4 text-sm font-semibold text-orange-900 hover:bg-orange-50 rounded-lg transition-colors border border-gray-200">
                  Sign In
                </a>
                <a href="#" className="block text-center w-full py-3 px-4 text-sm font-semibold text-white bg-orange-900 hover:bg-orange-800 rounded-lg transition-colors">
                  Create an account
                </a>
              </div>

              {/* Footer Support Info */}
              <div className="mt-auto pt-6 border-t border-gray-100">
                <span className="block text-xs text-gray-500 mb-1">Drop us a line</span>
                <a href="mailto:hello@trustvault.com" className="text-sm font-bold text-gray-900 hover:text-orange-900">
                  hello@trustvault.com
                </a>
              </div>
            </div>

          </div>
        )}
      </section>
    </div>
  )
}

export default App