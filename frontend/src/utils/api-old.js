import axios from 'axios';

// API configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:3001';

// Create axios instance with default config
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for logging and error handling
apiClient.interceptors.request.use(
  (config) => {
    console.log(`API Request: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    console.error('API Request Error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => {
    console.log(`API Response: ${response.status} ${response.config?.url}`);
    return response;
  },
  (error) => {
    console.error('API Response Error:', error);
    
    if (error.response) {
      // Server responded with error status
      const message = error.response.data?.message || error.response.data?.error || 'Server error';
      throw new Error(message);
    } else if (error.request) {
      // Request was made but no response received
      throw new Error('Network error - please check your connection');
    } else {
      // Something else happened
      throw new Error('Request failed - please try again');
    }
  }
);

// Main API call function
export const apiCall = async (endpoint, method = 'GET', data = null) => {
  try {
    let config = {
      method,
      url: endpoint,
    };

    if (method === 'GET' && data) {
      // For OSINT endpoints, convert data to query parameters
      const params = new URLSearchParams();
      if (data.username) params.append('value', data.username);
      if (data.email) params.append('value', data.email);
      if (data.domain) params.append('value', data.domain);
      if (data.ip) params.append('value', data.ip);
      
      config.url = `${endpoint}?${params.toString()}`;
    } else if (method === 'POST' && data) {
      config.data = data;
    }

    const response = await apiClient(config);
    return response.data;
  } catch (error) {
    console.error('API call failed:', error);
    throw error;
  }
};

// Generate unique request ID
function generateRequestId() {
  return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

// OSINT API functions
export const osintApi = {
  // Username investigation
  investigateUsername: async (username) => {
    const response = await api.get('/osint/username', {
      params: { value: username }
    });
    return response.data;
  },

  // Email investigation
  investigateEmail: async (email) => {
    const response = await api.get('/osint/email', {
      params: { value: email }
    });
    return response.data;
  },

  // Domain investigation
  investigateDomain: async (domain) => {
    const response = await api.get('/osint/domain', {
      params: { value: domain }
    });
    return response.data;
  },

  // IP investigation
  investigateIP: async (ip) => {
    const response = await api.get('/osint/ip', {
      params: { value: ip }
    });
    return response.data;
  },

  // File investigation
  investigateFile: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await api.post('/osint/file', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  // Hash investigation
  investigateHash: async (hash) => {
    const response = await api.post('/osint/file/hash', { hash });
    return response.data;
  },

  // Get API health status
  getHealthStatus: async () => {
    const response = await api.get('/health');
    return response.data;
  },

  // Get API documentation
  getApiDocs: async () => {
    const response = await api.get('/');
    return response.data;
  },

  // Get help for specific endpoint
  getHelp: async (type) => {
    const response = await api.get(`/osint/${type}/help`);
    return response.data;
  },
};

// Utility functions for API responses
export const apiUtils = {
  // Extract error message from API response
  getErrorMessage: (error) => {
    if (error.response?.data?.error?.message) {
      return error.response.data.error.message;
    }
    if (error.message) {
      return error.message;
    }
    return 'An unexpected error occurred';
  },

  // Check if error is a validation error
  isValidationError: (error) => {
    return error.response?.data?.error?.type === 'VALIDATION_ERROR';
  },

  // Check if error is a rate limit error
  isRateLimitError: (error) => {
    return error.response?.status === 429 || 
           error.response?.data?.error?.type === 'RATE_LIMIT_EXCEEDED';
  },

  // Format API response for display
  formatResponse: (response) => {
    return {
      success: response.success,
      data: response.data,
      meta: response.meta,
      timestamp: new Date().toISOString(),
    };
  },

  // Get risk level color for UI
  getRiskColor: (riskLevel) => {
    const colors = {
      none: 'text-gray-600 bg-gray-100',
      low: 'text-success-700 bg-success-50',
      medium: 'text-warning-700 bg-warning-50',
      high: 'text-danger-700 bg-danger-50',
      critical: 'text-critical-700 bg-critical-50',
      unknown: 'text-gray-600 bg-gray-100',
    };
    return colors[riskLevel] || colors.unknown;
  },

  // Get risk level emoji
  getRiskEmoji: (riskLevel) => {
    const emojis = {
      none: '✅',
      low: '🟢',
      medium: '🟡',
      high: '🔴',
      critical: '🚨',
      unknown: '❓',
    };
    return emojis[riskLevel] || emojis.unknown;
  },

  // Format timestamp for display
  formatTimestamp: (timestamp) => {
    return new Date(timestamp).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  },

  // Calculate processing time
  calculateProcessingTime: (startTime, endTime) => {
    const diff = new Date(endTime) - new Date(startTime);
    if (diff < 1000) {
      return `${diff}ms`;
    }
    return `${(diff / 1000).toFixed(2)}s`;
  },

  // Validate input based on type
  validateInput: (type, value) => {
    const validators = {
      username: (val) => /^[a-zA-Z0-9_-]+$/.test(val) && val.length >= 1 && val.length <= 50,
      email: (val) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val),
      domain: (val) => /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(val),
      ip: (val) => {
        // IPv4 regex
        const ipv4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        // Basic IPv6 regex (simplified)
        const ipv6 = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        return ipv4.test(val) || ipv6.test(val);
      },
      hash: (val) => {
        // MD5, SHA1, or SHA256
        return /^[a-fA-F0-9]{32}$/.test(val) || // MD5
               /^[a-fA-F0-9]{40}$/.test(val) || // SHA1
               /^[a-fA-F0-9]{64}$/.test(val);   // SHA256
      }
    };

    const validator = validators[type];
    return validator ? validator(value) : false;
  },

  // Get validation error message
  getValidationError: (type, value) => {
    const errors = {
      username: 'Username must contain only alphanumeric characters, hyphens, and underscores (1-50 characters)',
      email: 'Please enter a valid email address',
      domain: 'Please enter a valid domain name (e.g., example.com)',
      ip: 'Please enter a valid IP address (IPv4 or IPv6)',
      hash: 'Please enter a valid hash (MD5, SHA1, or SHA256)',
    };
    return errors[type] || 'Invalid input format';
  }
};

export default api;
