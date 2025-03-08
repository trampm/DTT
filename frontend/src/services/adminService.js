import axios from 'axios';
import authService from './authService';

const API_URL = 'http://localhost:8080/auth'; // Adjust as necessary
const USERS_API_URL = 'http://localhost:8080/users'; // Adjust as necessary

const createRole = async (roleData) => {
    const accessToken = authService.getAccessToken();
    try {
        const response = await axios.post(`${API_URL}/roles`, roleData, {
            headers: { Authorization: `Bearer ${accessToken}` },
        });
        return response.data;
    } catch (error) {
        throw await handleApiError(error);
    }
};

const createPermission = async (permissionData) => {
    const accessToken = authService.getAccessToken();
    try {
        const response = await axios.post(`${API_URL}/permissions`, permissionData, {
            headers: { Authorization: `Bearer ${accessToken}` },
        });
        return response.data;
    } catch (error) {
        throw await handleApiError(error);
    }
};

const assignRoleToUser = async (assignmentData) => {
    const accessToken = authService.getAccessToken();
    try {
        const response = await axios.post(`${API_URL}/roles/assign`, assignmentData, {
            headers: { Authorization: `Bearer ${accessToken}` },
        });
        return response.data;
    } catch (error) {
        throw await handleApiError(error);
    }
};

const assignPermissionToRole = async (assignmentData) => {
    const accessToken = authService.getAccessToken();
    try {
        const response = await axios.post(`${API_URL}/permissions/assign`, assignmentData, {
            headers: { Authorization: `Bearer ${accessToken}` },
        });
        return response.data;
    } catch (error) {
        throw await handleApiError(error);
    }
};

const getUsers = async () => {
    const accessToken = authService.getAccessToken();
    try {
        const response = await axios.get(USERS_API_URL, {
            headers: { Authorization: `Bearer ${accessToken}` },
        });
        return response.data;
    } catch (error) {
        throw await handleApiError(error);
    }
};

const getRoles = async () => {
    const accessToken = authService.getAccessToken();
    try {
        const response = await axios.get(`${API_URL}/roles`, {
            headers: { Authorization: `Bearer ${accessToken}` },
        });
        return response.data;
    } catch (error) {
        throw await handleApiError(error);
    }
};

const getPermissions = async () => {
    const accessToken = authService.getAccessToken();
    try {
        const response = await axios.get(`${API_URL}/permissions`, {
            headers: { Authorization: `Bearer ${accessToken}` },
        });
        return response.data;
    } catch (error) {
        throw await handleApiError(error);
    }
};

const handleApiError = async (error) => {
    if (error.response && error.response.status === 401) {
        const newAccessToken = await authService.refreshAccessToken();
        if (newAccessToken) {
            // Re-assign the new access token globally for future requests
            axios.defaults.headers.common['Authorization'] = `Bearer ${newAccessToken}`;
            // The original error is thrown back to the caller
            return error;
        } else {
            // Refresh failed - redirect to login or handle as appropriate
            authService.logout(); // Ensure logout and cleanup
            throw error;
        }
    }
    // For non-401 errors, just re-throw
    return error;
}

const adminService = {
    createRole,
    createPermission,
    assignRoleToUser,
    assignPermissionToRole,
    getUsers,
    getRoles,
    getPermissions,
};

export default adminService;