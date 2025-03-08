import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import authService from '../../services/authService';
import { Typography, Container } from '@mui/material';

const Logout = () => {
    const navigate = useNavigate();

    useEffect(() => {
        const logoutUser = async () => {
            try {
                await authService.logout();
                navigate('/login'); // Redirect to login after successful logout
            } catch (error) {
                console.error("Error during logout:", error);
                // Handle logout error - could display an error message or redirect to a default page.
                navigate('/login'); // Even if logout fails, redirect to login for now.
            }
        };

        logoutUser(); // Call the logout function when the component mounts.
    }, [navigate]);

    return (
        <Container maxWidth="sm">
            <Typography variant="body1" align="center">
                Logging out...
            </Typography>
        </Container>
    );
};

export default Logout;