import axios from 'axios';
import { jwtDecode } from 'jwt-decode';

const API_URL = 'http://localhost:8080/auth';  // Измени на адрес твоего Go API

const register = async (name, email, password) => {
  try {
    const response = await axios.post(`${API_URL}/register`, { name, email, password });
    return response.data; // Или что возвращает твой API
  } catch (error) {
    throw error; // Очень важно пробрасывать ошибки дальше для обработки в компонентах
  }
};

const login = async (email, password) => {
  try {
    const response = await axios.post(`${API_URL}/login`, { email, password });

    if (response.data.access_token) {
      localStorage.setItem('accessToken', response.data.access_token);
      localStorage.setItem('refreshToken', response.data.refresh_token); // Сохраняем refresh токен
    }
    return response.data;
  } catch (error) {
    throw error;
  }
};

const logout = async () => {
  try {
      const refreshToken = localStorage.getItem('refreshToken');
      if(!refreshToken) return; // nothing to do

      await axios.post(`${API_URL}/logout`, { refresh_token: refreshToken });
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');
  } catch (error) {
      // Ideally, handle the error appropriately, e.g., log it or display a message.
      console.error("Error during logout:", error);
      //  Even if logout fails, it's often best to clear the tokens from local storage
      //  to prevent accidental reuse.
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');
  }
};

const refreshAccessToken = async () => {
    try {
        const refreshToken = localStorage.getItem('refreshToken');
        if (!refreshToken) {
            return null; // No refresh token available
        }

        const response = await axios.post(`${API_URL}/refresh`, { refresh_token: refreshToken });

        if (response.data.access_token) {
            localStorage.setItem('accessToken', response.data.access_token);
            return response.data.access_token;
        } else {
            // Refresh failed - token probably invalid. Clear tokens and redirect to login.
            localStorage.removeItem('accessToken');
            localStorage.removeItem('refreshToken');
            return null;
        }
    } catch (error) {
        console.error("Error refreshing token:", error);
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        return null;
    }
};

// Helper function to get user details from the token (using jwt-decode)
const getAccessToken = () => {
    return localStorage.getItem('accessToken');
};

const getUser = () => {
  const accessToken = localStorage.getItem('accessToken');
  if (accessToken) {
    try {
      return jwtDecode(accessToken); // Decode the token to get user info.
    } catch (error) {
      console.error("Error decoding token:", error);
      return null;
    }
  }
  return null;
};

const initiatePasswordReset = async (email) => {
  try {
    const response = await axios.post(`${API_URL}/password-reset`, { email });
    return response.data;
  } catch (error) {
    throw error;
  }
};

const resetPassword = async (token, new_password) => {
  try {
    const response = await axios.post(`${API_URL}/password-reset/confirm`, { token, new_password });
    return response.data;
  } catch (error) {
    throw error;
  }
};

const authService = {
  register,
  login,
  logout,
  refreshAccessToken,
  getAccessToken,
  getUser,
  initiatePasswordReset,
  resetPassword,
};

export default authService;