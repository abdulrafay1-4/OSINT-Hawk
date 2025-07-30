import React, { useState } from 'react';
import { FaSearch, FaSpinner, FaExclamationTriangle, FaInfoCircle } from 'react-icons/fa';
import { apiUtils } from '../utils/api';

const ScanForm = ({ onSubmit, isLoading }) => {
  const [scanType, setScanType] = useState('username');
  const [inputValue, setInputValue] = useState('');
  const [validationError, setValidationError] = useState('');

  const scanTypes = [
    { id: 'username', label: 'Username', placeholder: 'Enter username (e.g., johndoe)', icon: '👤' },
    { id: 'email', label: 'Email', placeholder: 'Enter email address (e.g., user@example.com)', icon: '📧' },
    { id: 'domain', label: 'Domain', placeholder: 'Enter domain (e.g., example.com)', icon: '🌐' },
    { id: 'ip', label: 'IP Address', placeholder: 'Enter IP address (e.g., 8.8.8.8)', icon: '🌍' },
    { id: 'file', label: 'File Upload', placeholder: 'Upload file for analysis', icon: '📁' },
    { id: 'hash', label: 'File Hash', placeholder: 'Enter file hash (MD5, SHA1, or SHA256)', icon: '🔒' }
  ];

  const getCurrentScanType = () => scanTypes.find(type => type.id === scanType);

  // Validate input before submission
  const validateInput = useCallback((type, value) => {
    if (!value || (typeof value === 'string' && value.trim() === '')) {
      return 'Input is required';
    }

    if (type !== 'file' && !apiUtils.validateInput(type, value.trim())) {
      return apiUtils.getValidationError(type, value);
    }

    return '';
  }, []);

  // Handle input change with real-time validation
  const handleInputChange = (value) => {
    setInputValue(value);
    
    if (value.trim()) {
      const error = validateInput(scanType, value);
      setValidationError(error);
    } else {
      setValidationError('');
    }
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

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white flex items-center">
          <FaSearch className="mr-2 text-primary-600" />
          OSINT Investigation
        </h2>
        <p className="text-gray-600 dark:text-gray-400 mt-1">
          Select investigation type and enter target information
        </p>
      </div>

      <div className="card-body">
        {/* Scan Type Selection */}
        <div className="mb-6">
          <label className="label">Investigation Type</label>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {scanTypes.map((type) => (
              <button
                key={type.id}
                type="button"
                onClick={() => handleScanTypeChange(type.id)}
                className={`p-3 text-left border rounded-lg transition-all duration-200 ${
                  scanType === type.id
                    ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300'
                    : 'border-gray-300 dark:border-gray-600 hover:border-gray-400 dark:hover:border-gray-500'
                }`}
              >
                <div className="flex items-center">
                  <span className="text-lg mr-2">{type.icon}</span>
                  <span className="font-medium">{type.label}</span>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Input Form */}
        {scanType !== 'file' && (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="label" htmlFor="scan-input">
                {getCurrentScanType().label}
              </label>
              <div className="relative">
                <input
                  id="scan-input"
                  type="text"
                  value={inputValue}
                  onChange={(e) => handleInputChange(e.target.value)}
                  placeholder={getCurrentScanType().placeholder}
                  className={`input pr-12 ${
                    validationError 
                      ? 'border-red-500 focus:border-red-500 focus:ring-red-500' 
                      : ''
                  }`}
                  disabled={isLoading}
                />
                <div className="absolute inset-y-0 right-0 flex items-center pr-3">
                  {isLoading ? (
                    <FaSpinner className="animate-spin text-primary-500" />
                  ) : validationError ? (
                    <FaExclamationTriangle className="text-red-500" />
                  ) : (
                    <span className="text-2xl">{getCurrentScanType().icon}</span>
                  )}
                </div>
              </div>
              
              {validationError && (
                <p className="mt-1 text-sm text-red-600 dark:text-red-400 flex items-center">
                  <FaExclamationTriangle className="mr-1" />
                  {validationError}
                </p>
              )}
            </div>

            <button
              type="submit"
              disabled={isLoading || !!validationError || !inputValue.trim()}
              className="btn-primary w-full"
            >
              {isLoading ? (
                <>
                  <FaSpinner className="animate-spin mr-2" />
                  Investigating...
                </>
              ) : (
                <>
                  <FaSearch className="mr-2" />
                  Start Investigation
                </>
              )}
            </button>
          </form>
        )}

        {/* File Upload Info */}
        {scanType === 'file' && (
          <div className="text-center py-8">
            <div className="text-6xl mb-4">📁</div>
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
              File Upload
            </h3>
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              Use the file upload component below to analyze files
            </p>
            <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
              <div className="flex items-start">
                <FaInfoCircle className="text-blue-500 mt-0.5 mr-2" />
                <div className="text-left">
                  <p className="text-sm text-blue-800 dark:text-blue-200 font-medium mb-1">
                    Supported file types:
                  </p>
                  <p className="text-sm text-blue-700 dark:text-blue-300">
                    .exe, .dll, .doc, .docx, .pdf, .zip, .rar, .txt, .bat, .ps1 and more
                  </p>
                  <p className="text-xs text-blue-600 dark:text-blue-400 mt-2">
                    Maximum file size: 50MB
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Quick Examples */}
        <div className="mt-6 pt-6 border-t border-gray-200 dark:border-gray-700">
          <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
            💡 Quick Examples:
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
            {getExamples(scanType).map((example, index) => (
              <button
                key={index}
                type="button"
                onClick={() => handleInputChange(example.value)}
                className="text-left p-2 bg-gray-50 dark:bg-gray-800 rounded border border-gray-200 dark:border-gray-700 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                disabled={isLoading}
              >
                <span className="font-mono text-primary-600 dark:text-primary-400">
                  {example.value}
                </span>
                <span className="text-gray-500 dark:text-gray-400 ml-2">
                  - {example.description}
                </span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

// Get examples for each scan type
const getExamples = (scanType) => {
  const examples = {
    username: [
      { value: 'octocat', description: 'GitHub username' },
      { value: 'testuser123', description: 'Common username pattern' },
    ],
    email: [
      { value: 'test@gmail.com', description: 'Gmail address' },
      { value: 'user@10minutemail.com', description: 'Disposable email' },
    ],
    domain: [
      { value: 'github.com', description: 'Popular platform' },
      { value: 'example.com', description: 'Standard test domain' },
    ],
    ip: [
      { value: '8.8.8.8', description: 'Google DNS' },
      { value: '1.1.1.1', description: 'Cloudflare DNS' },
    ],
    hash: [
      { value: 'd41d8cd98f00b204e9800998ecf8427e', description: 'MD5 hash' },
      { value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', description: 'SHA256 hash' },
    ],
  };

  return examples[scanType] || [];
};

export default ScanForm;
