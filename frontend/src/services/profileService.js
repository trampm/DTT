import axios from 'axios';
import authService from './authService';

const API_URL = 'http://localhost:8080/profile';  // Измени на адрес твоего Go API

const getProfile = async () => {
  const accessToken = authService.getAccessToken();

  if (!accessToken) {
    throw new Error('No access token available'); // Or redirect to login
  }

  try {
    const response = await axios.get(API_URL, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });
    return response.data;
  } catch (error) {
    // Token expired - try to refresh
    if (error.response && error.response.status === 401) {
      const newAccessToken = await authService.refreshAccessToken();
      if (newAccessToken) {
        // Retry the request with the new token
        const response = await axios.get(API_URL, {
          headers: {
            Authorization: `Bearer ${newAccessToken}`,
          },
        });
        return response.data;
      } else {
        // Refresh failed - redirect to login
        throw error;
      }
    }
    throw error;
  }
};

const updateProfile = async (profileData) => {
  const accessToken = authService.getAccessToken();

  if (!accessToken) {
    throw new Error('No access token available'); // Or redirect to login
  }

  try {
    const response = await axios.put(API_URL, profileData, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });
    return response.data;
  } catch (error) {
    // Token expired - try to refresh
    if (error.response && error.response.status === 401) {
      const newAccessToken = await authService.refreshAccessToken();
      if (newAccessToken) {
        // Retry the request with the new token
        const response = await axios.put(API_URL, profileData, {
          headers: {
            Authorization: `Bearer ${newAccessToken}`,
          },
        });
        return response.data;
      } else {
        // Refresh failed - redirect to login
        throw error;
      }
    }
    throw error;
  }
};

const profileService = {
  getProfile,
  updateProfile,
};

export default profileService;