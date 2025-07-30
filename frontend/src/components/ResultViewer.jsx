import React from 'react';
import { exportData } from '../utils/exportUtils';

const ResultViewer = ({ results, type, isLoading, error }) => {
  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
        <span className="ml-3 text-gray-600 dark:text-gray-300">Investigating...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-6">
        <div className="flex items-center">
          <svg className="h-5 w-5 text-red-500 mr-3" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
          </svg>
          <h3 className="text-red-800 dark:text-red-200 font-medium">Investigation Failed</h3>
        </div>
        <p className="text-red-700 dark:text-red-300 mt-2">{error}</p>
      </div>
    );
  }

  if (!results) {
    return null;
  }

  const getRiskLevel = () => {
    if (!results.risk_level) return 'unknown';
    return results.risk_level.toLowerCase();
  };

  const getRiskColor = (level) => {
    switch (level) {
      case 'low': return 'text-green-600 bg-green-100 dark:bg-green-900/20 dark:text-green-400';
      case 'medium': return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900/20 dark:text-yellow-400';
      case 'high': return 'text-red-600 bg-red-100 dark:bg-red-900/20 dark:text-red-400';
      default: return 'text-gray-600 bg-gray-100 dark:bg-gray-800 dark:text-gray-400';
    }
  };

  const handleExport = (format) => {
    const filename = `osint_${type}_${results.target || 'result'}`;
    exportData(results, format, filename);
  };

  const renderValue = (value) => {
    if (typeof value === 'boolean') {
      return value ? (
        <span className="text-green-600 dark:text-green-400">✓ Yes</span>
      ) : (
        <span className="text-red-600 dark:text-red-400">✗ No</span>
      );
    }
    if (typeof value === 'object' && value !== null) {
      return (
        <div className="ml-4">
          {Object.entries(value).map(([key, val]) => (
            <div key={key} className="mb-2">
              <span className="font-medium text-gray-700 dark:text-gray-300">{key}:</span>
              <span className="ml-2 text-gray-600 dark:text-gray-400">{renderValue(val)}</span>
            </div>
          ))}
        </div>
      );
    }
    if (Array.isArray(value)) {
      return (
        <ul className="ml-4 space-y-1">
          {value.map((item, index) => (
            <li key={index} className="text-gray-600 dark:text-gray-400">
              • {typeof item === 'object' ? JSON.stringify(item) : item}
            </li>
          ))}
        </ul>
      );
    }
    return <span className="text-gray-600 dark:text-gray-400">{value || 'N/A'}</span>;
  };

  const riskLevel = getRiskLevel();

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-4">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
            Investigation Results
          </h2>
          <span className={`px-3 py-1 rounded-full text-sm font-medium ${getRiskColor(riskLevel)}`}>
            Risk Level: {riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1)}
          </span>
        </div>
        
        {/* Export Buttons */}
        <div className="flex space-x-2">
          <button
            onClick={() => handleExport('json')}
            className="px-3 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors text-sm"
          >
            JSON
          </button>
          <button
            onClick={() => handleExport('html')}
            className="px-3 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors text-sm"
          >
            HTML
          </button>
          <button
            onClick={() => handleExport('csv')}
            className="px-3 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition-colors text-sm"
          >
            CSV
          </button>
          <button
            onClick={() => handleExport('txt')}
            className="px-3 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 transition-colors text-sm"
          >
            TXT
          </button>
        </div>
      </div>

      {/* Basic Info */}
      {results.target && (
        <div className="mb-6 p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Target Information</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <span className="font-medium text-gray-700 dark:text-gray-300">Target:</span>
              <span className="ml-2 text-gray-600 dark:text-gray-400 font-mono">{results.target}</span>
            </div>
            <div>
              <span className="font-medium text-gray-700 dark:text-gray-300">Type:</span>
              <span className="ml-2 text-gray-600 dark:text-gray-400 capitalize">{type}</span>
            </div>
            {results.timestamp && (
              <div>
                <span className="font-medium text-gray-700 dark:text-gray-300">Investigated:</span>
                <span className="ml-2 text-gray-600 dark:text-gray-400">
                  {new Date(results.timestamp).toLocaleString()}
                </span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Summary Section */}
      {results.summary && (
        <div className="mb-6 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
          <h3 className="text-lg font-semibold text-blue-900 dark:text-blue-200 mb-2">Summary</h3>
          <p className="text-blue-800 dark:text-blue-300">{results.summary}</p>
        </div>
      )}

      {/* Data Sections */}
      <div className="space-y-6">
        {Object.entries(results).map(([key, value]) => {
          // Skip meta fields that we've already displayed
          if (['target', 'type', 'timestamp', 'summary', 'risk_level'].includes(key)) {
            return null;
          }

          return (
            <div key={key} className="border-l-4 border-blue-500 pl-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3 capitalize">
                {key.replace(/_/g, ' ')}
              </h3>
              <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                {renderValue(value)}
              </div>
            </div>
          );
        })}
      </div>

      {/* Recommendations */}
      {results.recommendations && (
        <div className="mt-6 p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
          <h3 className="text-lg font-semibold text-yellow-900 dark:text-yellow-200 mb-2">
            Recommendations
          </h3>
          <ul className="text-yellow-800 dark:text-yellow-300 space-y-1">
            {results.recommendations.map((rec, index) => (
              <li key={index}>• {rec}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Footer */}
      <div className="mt-6 pt-4 border-t border-gray-200 dark:border-gray-600">
        <p className="text-xs text-gray-500 dark:text-gray-400 text-center">
          Investigation completed by OSINT Hawk • Results are provided for informational purposes only
        </p>
      </div>
    </div>
  );
};

export default ResultViewer;
