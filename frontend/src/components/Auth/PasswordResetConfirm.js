import React, { useState } from 'react';
import authService from '../../services/authService';
import { useNavigate, useLocation } from 'react-router-dom';
import { TextField, Button, Container, Typography, Alert } from '@mui/material';

const PasswordResetConfirm = () => {
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [error, setError] = useState('');
    const [message, setMessage] = useState('');
    const navigate = useNavigate();
    const location = useLocation(); // Access location to get the token from the URL

    // Extract the token from the URL's query parameters.
    const searchParams = new URLSearchParams(location.search);
    const token = searchParams.get('token'); // Example: /password-reset/confirm?token=YOUR_TOKEN

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setMessage('');

        if (!token) {
            setError('Неверная ссылка для сброса пароля.');
            return;
        }

        if (newPassword !== confirmPassword) {
            setError('Пароли не совпадают.');
            return;
        }

        try {
            await authService.resetPassword(token, newPassword); // Assume this function exists in authService
            setMessage('Ваш пароль успешно изменен. Сейчас вы будете перенаправлены на страницу входа.');
            setTimeout(() => {
                navigate('/login');
            }, 3000); // Redirect after 3 seconds
        } catch (err) {
            setError(err.response?.data?.message || 'Произошла ошибка при сбросе пароля.');
        }
    };

    return (
        <Container maxWidth="sm">
            <Typography variant="h4" align="center" gutterBottom>
                Подтверждение сброса пароля
            </Typography>
            {message && <Alert severity="success">{message}</Alert>}
            {error && <Alert severity="error">{error}</Alert>}
            <form onSubmit={handleSubmit}>
                <TextField
                    fullWidth
                    margin="normal"
                    label="Новый пароль"
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    required
                />
                <TextField
                    fullWidth
                    margin="normal"
                    label="Подтвердите новый пароль"
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    required
                />
                <Button type="submit" variant="contained" color="primary" fullWidth>
                    Сбросить пароль
                </Button>
            </form>
        </Container>
    );
};

export default PasswordResetConfirm;