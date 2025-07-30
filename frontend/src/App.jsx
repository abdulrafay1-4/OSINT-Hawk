import React, { useState } from 'react';
import ScanForm from './components/ScanForm';
import ResultViewer from './components/ResultViewer';
import FileUpload from './components/FileUpload';
import ThemeToggle from './components/ThemeToggle';
import { apiCall } from './utils/api';

function App() {
  const [results, setResults] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('investigate');
  const [investigationType, setInvestigationType] = useState('username');

  const handleInvestigation = async (data) => {
    setIsLoading(true);
    setError(null);
    setResults(null);

    try {
      const endpoint = `/osint/${data.type}`;
      const payload = { [data.type]: data.target };
      
      const response = await apiCall(endpoint, 'GET', payload);
      
      // Extract the actual data from the response
      const results = response.success ? response.data : response;
      setResults(results);
      setInvestigationType(data.type);
    } catch (err) {
      setError(err.message || 'Investigation failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileUpload = async (file) => {
    setIsLoading(true);
    setError(null);
    setResults(null);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('http://localhost:3001/osint/file', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'File upload failed');
      }

      const result = await response.json();
      setResults(result);
      setInvestigationType('file');
    } catch (err) {
      setError(err.message || 'File upload failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const tabs = [
    { id: 'investigate', label: 'Investigate', icon: '🕵️' },
    { id: 'files', label: 'File Analysis', icon: '📁' },
  ];

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors duration-200">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo and Title */}
            <div className="flex items-center space-x-3">
              <div className="flex-shrink-0">
                <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-purple-600 rounded-lg flex items-center justify-center">
                  <span className="text-white font-bold text-lg">🦅</span>
                </div>
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                  OSINT Hawk
                </h1>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Open Source Intelligence Platform
                </p>
              </div>
            </div>

            {/* Theme Toggle */}
            <ThemeToggle />
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-6">
        <div className="border-b border-gray-200 dark:border-gray-700">
          <nav className="-mb-px flex space-x-8">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`py-2 px-1 border-b-2 font-medium text-sm flex items-center space-x-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300'
                }`}
              >
                <span>{tab.icon}</span>
                <span>{tab.label}</span>
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left Panel - Input Forms */}
          <div className="lg:col-span-1">
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
              {activeTab === 'investigate' && (
                <div>
                  <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
                    Start Investigation
                  </h2>
                  <ScanForm onSubmit={handleInvestigation} isLoading={isLoading} />
                  
                  {/* Investigation Info */}
                  <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                    <h3 className="text-sm font-semibold text-blue-900 dark:text-blue-200 mb-2">
                      🔍 What We Investigate
                    </h3>
                    <ul className="text-xs text-blue-800 dark:text-blue-300 space-y-1">
                      <li>• <strong>Usernames:</strong> Social media profiles, account existence</li>
                      <li>• <strong>Emails:</strong> Breach data, associated accounts</li>
                      <li>• <strong>Domains:</strong> WHOIS data, subdomains, security</li>
                      <li>• <strong>IP Addresses:</strong> Geolocation, reputation, services</li>
                    </ul>
                  </div>
                </div>
              )}

              {activeTab === 'files' && (
                <div>
                  <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
                    File Analysis
                  </h2>
                  <FileUpload
                    onUpload={handleFileUpload}
                    isUploading={isLoading}
                    error={error}
                  />
                </div>
              )}
            </div>

            {/* Security Notice */}
            <div className="mt-6 p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg border border-yellow-200 dark:border-yellow-800">
              <div className="flex items-start">
                <svg className="h-5 w-5 text-yellow-400 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-yellow-800 dark:text-yellow-200">
                    Security Notice
                  </h3>
                  <div className="mt-2 text-xs text-yellow-700 dark:text-yellow-300">
                    <p>• Use this tool responsibly and legally</p>
                    <p>• Respect privacy and terms of service</p>
                    <p>• Data is processed securely and not stored</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Right Panel - Results */}
          <div className="lg:col-span-2">
            {(results || isLoading || error) ? (
              <ResultViewer
                results={results}
                type={investigationType}
                isLoading={isLoading}
                error={error}
              />
            ) : (
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-12 text-center">
                <div className="mx-auto w-24 h-24 bg-gray-100 dark:bg-gray-700 rounded-full flex items-center justify-center mb-6">
                  <svg className="w-12 h-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                </div>
                <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                  Ready to Investigate
                </h3>
                <p className="text-gray-600 dark:text-gray-400 mb-6">
                  Start by entering a username, email, domain, IP address, or upload a file to analyze.
                </p>
                <div className="grid grid-cols-2 gap-4 max-w-md mx-auto">
                  <div className="text-center p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                    <div className="text-2xl mb-2">🔍</div>
                    <div className="text-sm font-medium text-gray-900 dark:text-white">Digital Footprint</div>
                    <div className="text-xs text-gray-600 dark:text-gray-400">Find online presence</div>
                  </div>
                  <div className="text-center p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                    <div className="text-2xl mb-2">🛡️</div>
                    <div className="text-sm font-medium text-gray-900 dark:text-white">Security Analysis</div>
                    <div className="text-xs text-gray-600 dark:text-gray-400">Check for threats</div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              OSINT Hawk - Open Source Intelligence Platform
            </p>
            <p className="text-xs text-gray-400 dark:text-gray-500 mt-2">
              Built for security professionals, researchers, and investigators. Use responsibly.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
