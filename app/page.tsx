'use client'

import { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ShieldCheckIcon, ExclamationTriangleIcon, ClockIcon, CheckCircleIcon, XCircleIcon, EyeIcon, CpuChipIcon } from '@heroicons/react/24/outline'
import toast from 'react-hot-toast'

interface VerificationResult {
  riskScore: number
  status: 'safe' | 'warning' | 'danger'
  flags: {
    type: 'green' | 'yellow' | 'red'
    message: string
  }[]
  domainInfo: {
    age: string
    registrar: string
    country: string
  }
  extractedInfo?: {
    companyName?: string
    website?: string
    contactPerson?: string
    offer?: string
  }
  summary: string
  suggestedAction: string
}

export default function Home() {
  const [emailContent, setEmailContent] = useState('')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [result, setResult] = useState<VerificationResult | null>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  const analyzeEmail = async () => {
    if (!emailContent.trim()) {
      toast.error('Please paste an email to analyze')
      return
    }

    setIsAnalyzing(true)
    setResult(null)
    
    try {
      console.log('Sending request to /api/verify...')
      const response = await fetch('/api/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ emailContent }),
      })

      console.log('Response status:', response.status)
      
      if (!response.ok) {
        const errorText = await response.text()
        console.error('Response error:', errorText)
        throw new Error(`Verification failed: ${response.status}`)
      }

      const data = await response.json()
      console.log('Analysis result:', data)
      setResult(data)
      toast.success('Analysis completed!')
    } catch (error) {
      console.error('Analysis error:', error)
      toast.error(`Failed to analyze email: ${error instanceof Error ? error.message : 'Unknown error'}`)
    } finally {
      setIsAnalyzing(false)
    }
  }

  const getRiskColor = (score: number) => {
    if (score <= 30) return 'text-emerald-400'
    if (score <= 70) return 'text-amber-400'
    return 'text-red-400'
  }

  const getRiskCardClass = (score: number) => {
    if (score <= 30) return 'risk-card-safe'
    if (score <= 70) return 'risk-card-warning'
    return 'risk-card-danger'
  }

  const getFlagClass = (type: string) => {
    switch (type) {
      case 'green': return 'flag-green'
      case 'yellow': return 'flag-yellow'
      case 'red': return 'flag-red'
      default: return 'flag-yellow'
    }
  }

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="header-blur border-b sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <motion.div 
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center space-x-4"
          >
            <div className="relative">
              <ShieldCheckIcon className="h-10 w-10 text-purple-400" />
              <div className="absolute -inset-2 bg-purple-500/20 rounded-full blur-lg"></div>
            </div>
            <h1 className="text-3xl font-bold gradient-text">SponsorGuard</h1>
            <div className="flex items-center space-x-2 text-sm text-purple-300">
              <CpuChipIcon className="h-5 w-5" />
              <span>AI-Powered Protection</span>
            </div>
          </motion.div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="grid lg:grid-cols-2 gap-8">
          {/* Input Section */}
          <motion.div 
            initial={{ opacity: 0, x: -50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.3, duration: 0.8 }}
                         className="space-y-6"
           >
             <div className="card p-8">
                             <h3 className="text-xl font-semibold mb-6 flex items-center">
                 <ExclamationTriangleIcon className="h-6 w-6 text-purple-400 mr-3" />
                 Paste Sponsor Email
               </h3>
              
                             <textarea
                 ref={textareaRef}
                 value={emailContent}
                 onChange={(e) => setEmailContent(e.target.value)}
                 placeholder="Copy and paste the entire sponsor email here for comprehensive analysis..."
                 className="input-field w-full h-64 resize-none text-base leading-relaxed"
                 disabled={isAnalyzing}
               />

              <div className="flex justify-between items-center mt-8">
                                 <p className="text-sm text-gray-400">
                   {emailContent.length.toLocaleString()} characters
                 </p>
                
                <button
                  onClick={analyzeEmail}
                  disabled={isAnalyzing || !emailContent.trim()}
                  className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-3"
                >
                  {isAnalyzing ? (
                    <>
                      <ClockIcon className="h-6 w-6 animate-spin" />
                      <span>Analyzing Security...</span>
                    </>
                  ) : (
                    <>
                      <ShieldCheckIcon className="h-6 w-6" />
                      <span>Verify Email</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Features */}
            <div className="grid grid-cols-2 gap-6">
              <motion.div 
                whileHover={{ scale: 1.02 }}
                className="card card-hover p-8"
              >
                <CheckCircleIcon className="h-10 w-10 text-emerald-400 mb-4" />
                <h4 className="font-semibold mb-3 text-lg">Multi-Layer Analysis</h4>
                <p className="text-sm text-gray-400 leading-relaxed">WHOIS verification, domain reputation, LinkedIn validation, phone number checks</p>
              </motion.div>
              
              <motion.div 
                whileHover={{ scale: 1.02 }}
                className="card card-hover p-8"
              >
                <XCircleIcon className="h-10 w-10 text-red-400 mb-4" />
                <h4 className="font-semibold mb-3 text-lg">Threat Detection</h4>
                <p className="text-sm text-gray-400 leading-relaxed">AI-powered scam pattern recognition and social engineering detection</p>
              </motion.div>
            </div>
          </motion.div>

          {/* Results Section */}
          <motion.div 
            initial={{ opacity: 0, x: 50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.6, duration: 0.8 }}
            className="space-y-8"
          >
            <AnimatePresence mode="wait">
              {result ? (
                <motion.div 
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.9 }}
                  transition={{ duration: 0.5 }}
                  className="space-y-8"
                >
                                                        {/* Compact Analysis Results */}
                   <div className="card p-6">
                     {/* Risk Score Header */}
                     <div className="flex items-center justify-between mb-6 pb-4 border-b border-purple-500/20">
                       <div className="flex items-center space-x-4">
                         <motion.div 
                           initial={{ scale: 0 }}
                           animate={{ scale: 1 }}
                           transition={{ delay: 0.2, type: "spring", stiffness: 200 }}
                           className={`text-3xl font-bold ${getRiskColor(result.riskScore)}`}
                         >
                           {result.riskScore}%
                         </motion.div>
                         <div>
                           <div className="text-sm text-gray-400">Risk Score</div>
                           <motion.div 
                             initial={{ opacity: 0 }}
                             animate={{ opacity: 1 }}
                             transition={{ delay: 0.4 }}
                             className={`inline-flex px-3 py-1 rounded-full text-xs font-bold ${
                               result.status === 'safe' ? 'bg-emerald-500/20 text-emerald-400' :
                               result.status === 'warning' ? 'bg-amber-500/20 text-amber-400' :
                               'bg-red-500/20 text-red-400'
                             }`}
                           >
                             {result.status.toUpperCase()}
                           </motion.div>
                         </div>
                       </div>
                     </div>

                     {/* Business Info Checklist */}
                     <div className="mb-6">
                       <h4 className="text-sm font-semibold text-purple-300 mb-3">Business Information</h4>
                       <div className="space-y-2 text-sm">
                         <div className="flex justify-between">
                           <span className="text-gray-400">Company:</span>
                           <span className="text-white font-medium">{result.extractedInfo?.companyName || 'Not specified'}</span>
                         </div>
                         <div className="flex justify-between">
                           <span className="text-gray-400">Website:</span>
                           <span className="text-white font-medium">{result.extractedInfo?.website || 'Not provided'}</span>
                         </div>
                         <div className="flex justify-between">
                           <span className="text-gray-400">Contact:</span>
                           <span className="text-white font-medium">{result.extractedInfo?.contactPerson || 'Not specified'}</span>
                         </div>
                         <div className="flex justify-between">
                           <span className="text-gray-400">Offer:</span>
                           <span className="text-white font-medium text-right max-w-[200px] truncate">{result.extractedInfo?.offer || 'Not specified'}</span>
                         </div>
                       </div>
                     </div>

                     {/* Security Checklist */}
                     <div className="mb-6">
                       <h4 className="text-sm font-semibold text-purple-300 mb-3">Security Checks</h4>
                       <div className="space-y-2">
                         {result.flags.map((flag, index) => (
                           <motion.div
                             key={index}
                             initial={{ opacity: 0, x: -10 }}
                             animate={{ opacity: 1, x: 0 }}
                             transition={{ delay: 0.1 * index }}
                             className="flex items-start space-x-3"
                           >
                             <div className={`w-3 h-3 rounded-full mt-1.5 flex-shrink-0 ${
                               flag.type === 'green' ? 'bg-emerald-400' :
                               flag.type === 'yellow' ? 'bg-amber-400' :
                               'bg-red-400'
                             }`} />
                             <span className="text-sm text-gray-300 leading-relaxed">{flag.message}</span>
                           </motion.div>
                         ))}
                       </div>
                     </div>

                     {/* Domain Info Checklist */}
                     <div className="mb-6">
                       <h4 className="text-sm font-semibold text-purple-300 mb-3">Domain Intelligence</h4>
                       <div className="space-y-2 text-sm">
                         <div className="flex justify-between">
                           <span className="text-gray-400">Age:</span>
                           <span className="text-white font-medium">{result.domainInfo.age}</span>
                         </div>
                         <div className="flex justify-between">
                           <span className="text-gray-400">Registrar:</span>
                           <span className="text-white font-medium">{result.domainInfo.registrar}</span>
                         </div>
                         <div className="flex justify-between">
                           <span className="text-gray-400">Country:</span>
                           <span className="text-white font-medium">{result.domainInfo.country}</span>
                         </div>
                       </div>
                     </div>

                     {/* Recommendation */}
                     <div className="pt-4 border-t border-purple-500/20">
                       <h4 className="text-sm font-semibold text-purple-300 mb-2">Recommendation</h4>
                       <p className="text-sm text-gray-300 leading-relaxed">{result.suggestedAction}</p>
                     </div>
                   </div>
                </motion.div>
              ) : (
                <motion.div 
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="card p-16 text-center"
                >
                  <ShieldCheckIcon className="h-20 w-20 text-purple-400/50 mx-auto mb-6" />
                  <h3 className="text-2xl font-semibold mb-4 text-gray-300">Ready for Analysis</h3>
                  <p className="text-gray-400 leading-relaxed">
                    Paste a sponsor email and click "Verify Email" to begin comprehensive security analysis
                  </p>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        </div>
      </main>
    </div>
  )
} 