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

// Validation utilities
export const apiUtils = {
  // Validate input based on type
  validateInput: (type, value) => {
    if (!value || typeof value !== 'string') return false;

    const validators = {
      username: (val) => /^[a-zA-Z0-9_-]{1,50}$/.test(val),
      email: (val) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val),
      domain: (val) => /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(val),
      ip: (val) => {
        // IPv4
        const ipv4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(val);
        // IPv6 (simplified)
        const ipv6 = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(val);
        return ipv4 || ipv6;
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
