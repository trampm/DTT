import React, { useState, useEffect } from 'react';
import profileService from '../../services/profileService';
import authService from '../../services/authService'; // Import authService
import { useNavigate } from 'react-router-dom';
import { Container, Typography, Button } from '@mui/material';

const Profile = () => {
  const [profile, setProfile] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const data = await profileService.getProfile();
        setProfile(data);
      } catch (error) {
        console.error("Error fetching profile:", error);
        // Handle the error, e.g., redirect to login if unauthorized
        if (error.response && error.response.status === 401) {
          navigate('/login');
        }
      }
    };

    fetchProfile();
  }, [navigate]);

  const handleUpdateProfileClick = () => {
    navigate('/update-profile'); // Navigate to the update profile page
  };

  const handleLogout = async () => {
    try {
      await authService.logout();
      navigate('/login');
    } catch (error) {
      console.error("Error logging out:", error);
      // Handle logout error (e.g., display an error message)
    }
  };

  if (!profile) {
    return <Typography>Loading profile...</Typography>;
  }

  return (
    <Container maxWidth="sm">
      <Typography variant="h4" align="center" gutterBottom>
        Your Profile
      </Typography>
      <Typography>ID: {profile.id}</Typography>
      <Typography>Email: {profile.email}</Typography>
      <Typography>First Name: {profile.first_name}</Typography>
      <Typography>Last Name: {profile.last_name}</Typography>
      {/* Display other profile details here */}
      <Button variant="contained" color="primary" onClick={handleUpdateProfileClick}>
        Update Profile
      </Button>
      <Button variant="contained" color="secondary" onClick={handleLogout}>
        Logout
      </Button>
    </Container>
  );
};

export default Profile;