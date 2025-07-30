import React, { useState } from 'react';
import { apiUtils } from '../utils/api';

const ScanForm = ({ onSubmit, isLoading }) => {
  const [scanType, setScanType] = useState('username');
  const [inputValue, setInputValue] = useState('');
  const [validationError, setValidationError] = useState('');

  // Validation function
  const validateInput = (type, value) => {
    if (!value || !value.trim()) {
      return 'Please enter a value to investigate';
    }

    if (type !== 'file' && !apiUtils.validateInput(type, value.trim())) {
      return apiUtils.getValidationError(type, value);
    }

    return null;
  };

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (scanType === 'file') {
      console.log('Please use the file upload area for file analysis');
      return;
    }

    const trimmedValue = inputValue.trim();
    const error = validateInput(scanType, trimmedValue);
    
    if (error) {
      setValidationError(error);
      return;
    }

    setValidationError('');
    
    // Call the parent's submit handler
    if (onSubmit) {
      onSubmit({
        type: scanType,
        target: trimmedValue
      });
    }
  };

  // Handle scan type change
  const handleScanTypeChange = (type) => {
    setScanType(type);
    setInputValue('');
    setValidationError('');
  };

  // Get current scan type info
  const getCurrentScanType = () => {
    const types = {
      username: { label: 'Username', placeholder: 'Enter username (e.g. johndoe)', example: 'johndoe' },
      email: { label: 'Email', placeholder: 'Enter email address (e.g. user@example.com)', example: 'user@example.com' },
      domain: { label: 'Domain', placeholder: 'Enter domain (e.g. example.com)', example: 'example.com' },
      ip: { label: 'IP Address', placeholder: 'Enter IP address (e.g. 192.168.1.1)', example: '192.168.1.1' },
    };
    return types[scanType] || types.username;
  };

  const scanTypeOptions = [
    { value: 'username', label: '👤 Username', description: 'Social media and account discovery' },
    { value: 'email', label: '📧 Email', description: 'Breach data and account linking' },
    { value: 'domain', label: '🌐 Domain', description: 'WHOIS data and DNS analysis' },
    { value: 'ip', label: '🔍 IP Address', description: 'Geolocation and threat intelligence' },
  ];

  const currentType = getCurrentScanType();

  return (
    <div className="space-y-6">
      {/* Investigation Type Selector */}
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
          Investigation Type
        </label>
        <div className="grid grid-cols-1 gap-2">
          {scanTypeOptions.map((option) => (
            <button
              key={option.value}
              type="button"
              onClick={() => handleScanTypeChange(option.value)}
              className={`p-3 text-left rounded-lg border transition-colors ${
                scanType === option.value
                  ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20 text-blue-900 dark:text-blue-200'
                  : 'border-gray-200 dark:border-gray-600 hover:border-gray-300 dark:hover:border-gray-500 text-gray-700 dark:text-gray-300'
              }`}
            >
              <div className="font-medium">{option.label}</div>
              <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                {option.description}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="investigation-input" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            {currentType.label}
          </label>
          <input
            id="investigation-input"
            type="text"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            placeholder={currentType.placeholder}
            disabled={isLoading}
            className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white ${
              validationError ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'
            } ${isLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
          />
          {validationError && (
            <p className="mt-2 text-sm text-red-600 dark:text-red-400 flex items-center">
              <span className="mr-1">⚠️</span>
              {validationError}
            </p>
          )}
        </div>

        <button
          type="submit"
          disabled={isLoading || !inputValue.trim()}
          className={`w-full py-3 px-4 rounded-lg font-medium transition-colors flex items-center justify-center ${
            isLoading || !inputValue.trim()
              ? 'bg-gray-300 dark:bg-gray-600 text-gray-500 dark:text-gray-400 cursor-not-allowed'
              : 'bg-blue-600 hover:bg-blue-700 text-white'
          }`}
        >
          {isLoading ? (
            <>
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
              Investigating...
            </>
          ) : (
            <>
              🔍 Start Investigation
            </>
          )}
        </button>
      </form>

      {/* Information Panel */}
      <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
        <div className="flex items-start">
          <span className="text-blue-500 text-lg mr-3">💡</span>
          <div>
            <h3 className="text-sm font-semibold text-blue-900 dark:text-blue-200 mb-2">
              Investigation Tips
            </h3>
            <ul className="text-xs text-blue-800 dark:text-blue-300 space-y-1">
              {scanType === 'username' && (
                <>
                  <li>• Try variations: with/without numbers, underscores</li>
                  <li>• Check across multiple social platforms</li>
                  <li>• Consider similar usernames or aliases</li>
                </>
              )}
              {scanType === 'email' && (
                <>
                  <li>• Check for data breaches and leaks</li>
                  <li>• Verify email domain reputation</li>
                  <li>• Look for associated accounts</li>
                </>
              )}
              {scanType === 'domain' && (
                <>
                  <li>• Analyze WHOIS registration data</li>
                  <li>• Check DNS records and subdomains</li>
                  <li>• Review security certificates</li>
                </>
              )}
              {scanType === 'ip' && (
                <>
                  <li>• Identify geolocation and ISP</li>
                  <li>• Check threat intelligence feeds</li>
                  <li>• Analyze network services</li>
                </>
              )}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanForm;
